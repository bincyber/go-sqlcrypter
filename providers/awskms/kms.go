package awskms

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/dgraph-io/ristretto"
	"github.com/pkg/errors"

	"github.com/bincyber/go-sqlcrypter"
)

// KMSCrypter is an implementation of the Crypterer interface
// using AWS KMS with envelope encryption.
type KMSCrypter struct {
	client *kms.Client

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
}

// New creates a new AWS KMS crypter given a KMS client and the ID/Alias/ARN of a KMS key.
// A new data encryption key (DEK) is obtained from KMS which will be stored alongside the
// ciphertext. 256-bit AES GCM is used to perform the encryption.
func New(ctx context.Context, client *kms.Client, keyID string) (sqlcrypter.Crypterer, error) {
	if client == nil {
		return nil, fmt.Errorf("kms.Client cannot be nil")
	}

	if keyID == "" {
		return nil, fmt.Errorf("keyID cannot be nil")
	}

	// Generate a symmetric data encryption key to encrypt new data
	p := &kms.GenerateDataKeyInput{
		KeyId:   aws.String(keyID),
		KeySpec: types.DataKeySpecAes256,
	}

	resp, err := client.GenerateDataKey(ctx, p)
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
		NumCounters: 100000000,
		MaxCost:     10000000, // 10MB
		BufferItems: 64,
	})

	if err != nil {
		return nil, errors.Wrap(err, "failed to configure in-memory cache")
	}

	k := &KMSCrypter{
		client:             client,
		keyID:              keyID,
		aesgcm:             aesgcm,
		encryptedKey:       resp.CiphertextBlob,
		encryptedKeyLength: uint8(len(resp.CiphertextBlob)),
		cache:              cache,
	}

	return k, nil
}

// Encrypt encrypts plaintext to ciphertext using the current DEK.
// The encrypted DEK is stored alongside the ciphertext.
func (k *KMSCrypter) Encrypt(w io.Writer, r io.Reader) error {
	src := new(bytes.Buffer)
	if _, err := src.ReadFrom(r); err != nil {
		return errors.Wrap(err, "failed to read from io.Reader")
	}

	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[4:], k.encryptedKeyEncryptionCount.Add(1))

	ciphertext := k.aesgcm.Seal(nil, nonce, src.Bytes(), nil)

	// First N bytes will be the length of the encrypted DEK, followed by the encrypted DEK.
	if err := binary.Write(w, binary.LittleEndian, k.encryptedKeyLength); err != nil {
		return errors.Wrap(err, "failed to write length of DEK to io.Writer")
	}
	w.Write(k.encryptedKey)

	// Next 12 bytes will be the nonce, followed by the ciphertext.
	w.Write(nonce)
	w.Write(ciphertext)

	return nil
}

// Decrypt decrypts ciphertext to plaintext. It first attempts to decrypt
// using the current DEK if it matches the encrypted key stored alongside
// the ciphertext. Otherwise, a request is made to KMS to decrypt the
// encrypted key and then the DEK is used to decrypt the ciphertext.
func (k *KMSCrypter) Decrypt(w io.Writer, r io.Reader) error {
	src := new(bytes.Buffer)
	n, err := src.ReadFrom(r)
	if err != nil {
		return errors.Wrap(err, "failed to read from io.Reader")
	}

	// First 2 bytes is the length of the encrypted DEK
	var keyLength uint8
	if err := binary.Read(src, binary.LittleEndian, &keyLength); err != nil {
		return errors.Wrap(err, "failed to read length of encrypted DEK")
	}

	// Next N bytes is the encrypted DEK
	encryptedKey := src.Next(int(keyLength))

	// Next 12 bytes is the nonce, followed by the ciphertext
	nonce := src.Next(12)
	ciphertext := src.Next(int(n))

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
			return fmt.Errorf("failed to type cast cache value as []byte")
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

	// Since the previous DEK doesn't exist in the cache, the DEK needs to be decrypted
	// using KMS. Then the decrypted key can be used to decrypt the ciphertext.
	p := &kms.DecryptInput{
		KeyId:          &k.keyID,
		CiphertextBlob: encryptedKey,
	}

	resp, err := k.client.Decrypt(context.TODO(), p)
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

var _ sqlcrypter.Crypterer = (*KMSCrypter)(nil)
