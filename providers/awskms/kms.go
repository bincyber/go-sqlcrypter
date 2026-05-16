package awskms

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/dgraph-io/ristretto"
	"github.com/pkg/errors"
	"golang.org/x/time/rate"

	"github.com/bincyber/go-sqlcrypter"
)

// defaultTimeout is the default timeout used for calls to AWS KMS.
const defaultTimeout = 2 * time.Second

// defaults for the in-memory DEK cache (see ristretto.Config).
const (
	defaultDEKCacheMaxCost     = int64(1 * 1024 * 1024) // 1 MB
	defaultDEKCacheNumCounters = int64(50_000)
	defaultDEKCacheBufferItems = int64(64) // 64 is the Ristretto-recommended default
)

// ErrKMSDecryptRateLimited is returned when optional KMS Decrypt rate limiting
// rejects a cache-miss decrypt before calling AWS KMS.
var ErrKMSDecryptRateLimited = errors.New("rate limit exceeded for KMS Decrypt")

// kmsAPI is the subset of AWS KMS client calls used by KMSCrypter (for testing with fakes).
type kmsAPI interface {
	GenerateDataKey(context.Context, *kms.GenerateDataKeyInput, ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// Option configures a KMSCrypter during New.
type Option func(*KMSCrypter) error

// WithRequestTimeout sets the per-KMS-call deadline for GenerateDataKey and Decrypt
// (encrypted DEK path). Values must be greater than zero. The default is 2 second.
func WithRequestTimeout(timeout time.Duration) Option {
	return func(k *KMSCrypter) error {
		if timeout <= 0 {
			return errors.New("request timeout must be greater than zero")
		}
		k.requestTimeout = timeout
		return nil
	}
}

// WithKMSDecryptRateLimit sets a token-bucket limit on KMS Decrypt calls (cache-miss path only).
// rps and burst must be greater than zero.
func WithKMSDecryptRateLimit(rps float64, burst int) Option {
	return func(k *KMSCrypter) error {
		if rps <= 0 {
			return errors.New("KMS decrypt rate limit rps must be greater than zero")
		}
		if burst <= 0 {
			return errors.New("KMS decrypt rate limit burst must be greater than zero")
		}
		k.decryptLimiter = rate.NewLimiter(rate.Limit(rps), burst)
		return nil
	}
}

// WithDEKCacheConfig sets the Ristretto configuration for the decrypted-DEK cache.
// NumCounters, MaxCost, and BufferItems must be greater than zero, and NumCounters
// must be at least MaxCost (see github.com/dgraph-io/ristretto documentation).
func WithDEKCacheConfig(cfg ristretto.Config) Option {
	return func(k *KMSCrypter) error {
		if cfg.NumCounters <= 0 {
			return errors.New("DEK cache NumCounters must be greater than zero")
		}
		if cfg.MaxCost <= 0 {
			return errors.New("DEK cache MaxCost must be greater than zero")
		}
		if cfg.BufferItems <= 0 {
			return errors.New("DEK cache BufferItems must be greater than zero")
		}
		if cfg.NumCounters < cfg.MaxCost {
			return errors.New("DEK cache NumCounters must be >= MaxCost")
		}
		k.cacheCounters = cfg.NumCounters
		k.cacheMaxCost = cfg.MaxCost
		k.cacheBufferItems = cfg.BufferItems
		return nil
	}
}

// KMSCrypter is an implementation of the Crypterer interface
// using AWS KMS with envelope encryption.
type KMSCrypter struct {
	client kmsAPI

	// keyID is the ID, ARN, or Alias for the KMS key.
	keyID string

	// encryptedKey is the data encryption key (DEK) used to encrypt new data.
	encryptedKey []byte

	// encryptedKeyLength is the length of the DEK.
	encryptedKeyLength uint8

	// encryptedKeyEncryptionCount is the number of encryptions performed with the current key
	encryptedKeyEncryptionCount atomic.Uint64

	// cipherBlock is the 256-bit AES GCM block cipher.
	aesgcm cipher.AEAD

	// cache stores any previous DEKs that were stored alongside ciphertext
	// to avoid repetitive client.Decrypt() calls to AWS KMS.
	cache *ristretto.Cache

	// cacheCounters, cacheMaxCost, and cacheBufferItems map to ristretto.Config (NumCounters, MaxCost, BufferItems).
	cacheCounters    int64
	cacheMaxCost     int64
	cacheBufferItems int64

	// requestTimeout caps each KMS API call (GenerateDataKey, Decrypt on miss).
	requestTimeout time.Duration

	// decryptLimiter, when non-nil, rate-limits KMS Decrypt on cache miss.
	decryptLimiter *rate.Limiter
}

// New creates a new AWS KMS crypter given a KMS client and the ID/Alias/ARN of a KMS key.
// A new data encryption key (DEK) is obtained from KMS which will be stored alongside the
// ciphertext. 256-bit AES GCM is used to perform the encryption.
//
// By default each KMS request uses a 2 second deadline. This can be overridden using WithRequestTimeout option.
// The decrypted-DEK Ristretto cache uses built-in defaults; override with WithDEKCacheConfig.
func New(ctx context.Context, client *kms.Client, keyID string, opts ...Option) (sqlcrypter.Crypterer, error) {
	if client == nil {
		return nil, errors.New("kms.Client cannot be nil")
	}

	if keyID == "" {
		return nil, errors.New("keyID cannot be empty")
	}

	k := &KMSCrypter{
		client:           client,
		keyID:            keyID,
		requestTimeout:   defaultTimeout,
		cacheCounters:    defaultDEKCacheNumCounters,
		cacheMaxCost:     defaultDEKCacheMaxCost,
		cacheBufferItems: defaultDEKCacheBufferItems,
	}

	for _, opt := range opts {
		if err := opt(k); err != nil {
			return nil, errors.Wrap(err, "failed to apply KMS crypter option")
		}
	}

	// Generate a symmetric data encryption key to encrypt new data
	p := &kms.GenerateDataKeyInput{
		KeyId:   aws.String(keyID),
		KeySpec: types.DataKeySpecAes256,
	}

	rCtx, cancel := context.WithTimeout(ctx, k.requestTimeout)
	defer cancel()

	resp, err := k.client.GenerateDataKey(rCtx, p)
	if err != nil {
		return nil, errors.Wrap(err, "failed to retrieve data key from AWS KMS")
	}

	cipherBlock, err := aes.NewCipher(resp.Plaintext)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new GCM block cipher")
	}

	// Create in-memory cache for previous DEKs
	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: k.cacheCounters,
		MaxCost:     k.cacheMaxCost,
		BufferItems: k.cacheBufferItems,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to configure in-memory cache")
	}

	dekLen := len(resp.CiphertextBlob)
	if dekLen > 255 {
		return nil, errors.New("encrypted DEK length exceeds uint8 limit")
	}

	k.aesgcm = aesgcm
	k.encryptedKey = resp.CiphertextBlob
	k.encryptedKeyLength = uint8(dekLen)
	k.cache = cache

	return k, nil
}

// Encrypt encrypts plaintext to ciphertext using the current DEK.
// The encrypted DEK is stored alongside the ciphertext.
func (k *KMSCrypter) Encrypt(w io.Writer, r io.Reader) error {
	if k.aesgcm == nil {
		return errors.New("AES-GCM was not initialized")
	}

	src := new(bytes.Buffer)
	if _, err := src.ReadFrom(r); err != nil {
		return errors.Wrap(err, "failed to read from io.Reader")
	}

	nonceSize := k.aesgcm.NonceSize() // 12 bytes
	nonce := make([]byte, nonceSize)
	binary.LittleEndian.PutUint64(nonce[4:], k.encryptedKeyEncryptionCount.Add(1))

	ciphertext := k.aesgcm.Seal(nil, nonce, src.Bytes(), nil)

	// First N bytes will be the length of the encrypted DEK, followed by the encrypted DEK.
	if err := binary.Write(w, binary.LittleEndian, k.encryptedKeyLength); err != nil {
		return errors.Wrap(err, "failed to write length of DEK to io.Writer")
	}
	w.Write(k.encryptedKey)

	// Next 12 bytes are the nonce, then the ciphertext (plaintext + AEAD overhead).
	w.Write(nonce)
	w.Write(ciphertext)

	return nil
}

// Decrypt decrypts ciphertext to plaintext. It first attempts to decrypt
// using the current DEK if it matches the encrypted key stored alongside
// the ciphertext. Otherwise, a request is made to KMS to decrypt the
// encrypted key and then the DEK is used to decrypt the ciphertext.
func (k *KMSCrypter) Decrypt(w io.Writer, r io.Reader) error {
	if k.aesgcm == nil {
		return errors.New("AES-GCM was not initialized")
	}

	src := new(bytes.Buffer)
	n, err := src.ReadFrom(r)
	if err != nil {
		return errors.Wrap(err, "failed to read from io.Reader")
	}

	// First byte is the length of the encrypted DEK
	var keyLength uint8
	if err := binary.Read(src, binary.LittleEndian, &keyLength); err != nil {
		return errors.Wrap(err, "failed to read length of encrypted DEK")
	}

	// crypto/cipher.AEAD.Open panics on wrong nonce length.
	// Validate that the buffer holds encryptedKey + nonce + at least AEAD.Overhead()
	// bytes remaining after the keyLength byte was consumed.
	nonceSize := k.aesgcm.NonceSize() // 12 bytes
	overhead := k.aesgcm.Overhead()   // 16 bytes

	minAfterKey := int64(keyLength) + int64(nonceSize+overhead)
	remaining := n - 1
	if remaining < minAfterKey {
		return errors.New("failed to read ciphertext: minimum length not met")
	}

	// Next N bytes is the encrypted DEK
	encryptedKey := src.Next(int(keyLength))
	if len(encryptedKey) != int(keyLength) {
		return errors.New("failed to read complete encrypted DEK")
	}

	nonce := src.Next(nonceSize)
	if len(nonce) != nonceSize {
		return errors.New("failed to read complete nonce")
	}
	ciphertext := src.Next(src.Len())

	// Decrypt using the current DEK
	if bytes.Equal(encryptedKey, k.encryptedKey) {
		plaintext, err := k.aesgcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return errors.Wrap(err, "failed to decrypt ciphertext")
		}

		w.Write(plaintext)
		return nil
	}

	// Check if the previous DEK exists in the cache, then use it to decrypt the ciphertext.
	if v, ok := k.cache.Get(encryptedKey); ok {
		key, ok := v.([]byte)
		if !ok {
			return errors.New("failed to type cast cache value as []byte")
		}

		cipherBlock, err := aes.NewCipher(key)
		if err != nil {
			return errors.Wrap(err, "failed to create new cipher.Block")
		}

		aesgcm, err := cipher.NewGCM(cipherBlock)
		if err != nil {
			return errors.Wrap(err, "failed to create new GCM block cipher")
		}

		plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return errors.Wrap(err, "failed to decrypt ciphertext")
		}

		w.Write(plaintext)
		return nil
	}

	if k.decryptLimiter != nil && !k.decryptLimiter.Allow() {
		return ErrKMSDecryptRateLimited
	}

	// Since the previous DEK doesn't exist in the cache, the DEK needs to be decrypted
	// using KMS. Then the decrypted key can be used to decrypt the ciphertext.
	p := &kms.DecryptInput{
		KeyId:          &k.keyID,
		CiphertextBlob: encryptedKey,
	}

	rCtx, cancel := context.WithTimeout(context.Background(), k.requestTimeout)
	defer cancel()

	resp, err := k.client.Decrypt(rCtx, p)
	if err != nil {
		return errors.Wrap(err, "failed to decrypt previous DEK using KMS")
	}

	cipherBlock, err := aes.NewCipher(resp.Plaintext)
	if err != nil {
		return errors.Wrap(err, "failed to create new cipher.Block")
	}

	aesgcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return errors.Wrap(err, "failed to create new GCM block cipher")
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return errors.Wrap(err, "failed to decrypt ciphertext")
	}

	w.Write(plaintext)

	// Store the decrypted DEK in the cache to avoid repetitive calls to AWS KMS.
	cost := int64(len(encryptedKey) + len(resp.Plaintext))
	k.cache.SetWithTTL(encryptedKey, resp.Plaintext, cost, 60*time.Minute)

	return nil
}

var (
	_ sqlcrypter.Crypterer = (*KMSCrypter)(nil)
	_ kmsAPI               = (*kms.Client)(nil)
)
