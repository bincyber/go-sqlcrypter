package awskms

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/dgraph-io/ristretto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/time/rate"

	"github.com/bincyber/go-sqlcrypter"
)

const (
	KmsKeyID    = "b8fac04c-ed81-4283-8857-7b9fce25bc3d"
	KmsKeyAlias = "alias/sqlcrypter"
)

// getLocalKMSClient returns a KMS client configured to make
// requests to local-kms: https://github.com/nsmithuk/local-kms
//
// See: https://aws.github.io/aws-sdk-go-v2/docs/configuring-sdk/endpoints/
func getLocalKMSClient() *kms.Client {
	cfg, _ := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion("us-west-2"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("AKID", "SECRET_KEY", "TOKEN")),
	)

	return kms.NewFromConfig(cfg, func(o *kms.Options) {
		o.BaseEndpoint = aws.String("http://localhost:9090")
	})
}

func getTestKMSClient(baseURL string) *kms.Client {
	cfg, _ := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion("us-west-2"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("AKID", "SECRET_KEY", "TOKEN")),
	)

	return kms.NewFromConfig(cfg, func(o *kms.Options) {
		o.BaseEndpoint = aws.String(baseURL)
	})
}

type KMSCrypterTestSuite struct {
	suite.Suite
	client     *kms.Client
	kmsCrypter sqlcrypter.Crypterer
}

func (s *KMSCrypterTestSuite) SetupTest() {
	s.client = getLocalKMSClient()

	kmsCrypter, _ := New(context.Background(), s.client, KmsKeyAlias)
	s.kmsCrypter = kmsCrypter
}

func (s *KMSCrypterTestSuite) Test_New() {
	r := s.Require()

	kmsCrypter, err := New(context.Background(), s.client, KmsKeyAlias)

	r.NoError(err)
	r.IsType(&KMSCrypter{}, kmsCrypter)
}

func (s *KMSCrypterTestSuite) Test_New_nil_kms_client() {
	r := s.Require()

	_, err := New(context.Background(), nil, KmsKeyID)
	r.Error(err)
}

func (s *KMSCrypterTestSuite) Test_New_nil_keyID() {
	r := s.Require()

	_, err := New(context.Background(), s.client, "")
	r.Error(err)
}

func (s *KMSCrypterTestSuite) Test_New_GenerateDataKey_error() {
	r := s.Require()

	cfg, err := config.LoadDefaultConfig(context.Background())
	r.NoError(err)

	client := kms.NewFromConfig(cfg)

	_, err = New(context.Background(), client, "nonexistant-kms-key")
	r.Error(err)
	r.Contains(err.Error(), "failed to retrieve data key")
}

func (s *KMSCrypterTestSuite) Test_Encrypt() {
	r := s.Require()

	plaintext := "Hello World"

	reader := bytes.NewBufferString(plaintext)
	writer := new(bytes.Buffer)

	err := s.kmsCrypter.Encrypt(writer, reader)
	r.NoError(err)
	r.NotEqual(plaintext, writer.String())

	// Verify the writer's contents is structured as expected
	var keyLength uint8
	err = binary.Read(writer, binary.LittleEndian, &keyLength)
	r.NoError(err)

	key := writer.Next(int(keyLength))
	kr := s.kmsCrypter.(*KMSCrypter)
	ns := kr.aesgcm.NonceSize()
	nonce := writer.Next(ns)
	ciphertext := writer.Next(27)

	r.Len(key, 140)
	r.Len(nonce, ns)
	r.Len(ciphertext, 27)
}

func (s *KMSCrypterTestSuite) Test_Decrypt_current_DEK() {
	r := s.Require()

	plaintext := "Hello World"

	reader := bytes.NewBufferString(plaintext)
	writer := new(bytes.Buffer)

	err := s.kmsCrypter.Encrypt(writer, reader)
	r.NoError(err)

	reader = new(bytes.Buffer)

	err = s.kmsCrypter.Decrypt(reader, writer)
	r.NoError(err)
	r.Equal(plaintext, reader.String())
}

func (s *KMSCrypterTestSuite) Test_Decrypt_previous_DEK() {
	r := s.Require()

	plaintext := "Hello World"

	ciphertext := []byte{0x8c, 0x4b, 0x61, 0x72, 0x6e, 0x3a, 0x61, 0x77, 0x73, 0x3a, 0x6b, 0x6d, 0x73, 0x3a, 0x65, 0x75, 0x2d, 0x77, 0x65, 0x73, 0x74, 0x2d, 0x32, 0x3a, 0x31, 0x31, 0x31, 0x31, 0x32, 0x32, 0x32, 0x32, 0x33, 0x33, 0x33, 0x33, 0x3a, 0x6b, 0x65, 0x79, 0x2f, 0x62, 0x38, 0x66, 0x61, 0x63, 0x30, 0x34, 0x63, 0x2d, 0x65, 0x64, 0x38, 0x31, 0x2d, 0x34, 0x32, 0x38, 0x33, 0x2d, 0x38, 0x38, 0x35, 0x37, 0x2d, 0x37, 0x62, 0x39, 0x66, 0x63, 0x65, 0x32, 0x35, 0x62, 0x63, 0x33, 0x64, 0x0, 0x0, 0x0, 0x0, 0xfb, 0x25, 0xe9, 0x99, 0xab, 0xde, 0xb8, 0xc4, 0x99, 0xbb, 0x1f, 0x79, 0x45, 0xb3, 0xe2, 0x53, 0x69, 0x65, 0x61, 0xa5, 0xae, 0xaa, 0x2f, 0x3b, 0x36, 0xaf, 0xce, 0xad, 0xfa, 0x4d, 0xc7, 0x42, 0x5, 0x3d, 0xd8, 0xcf, 0xea, 0x13, 0x11, 0xb5, 0x79, 0x87, 0x67, 0x3c, 0x54, 0x98, 0x5d, 0xeb, 0xa6, 0x1e, 0xd9, 0x89, 0xf1, 0x4c, 0x8d, 0x52, 0x65, 0x54, 0xb6, 0xf9, 0x87, 0xd0, 0x9b, 0xc2, 0x5f, 0x7e, 0x64, 0xa, 0xdf, 0x3, 0xb3, 0xea, 0x70, 0xb8, 0x7d, 0xb8, 0x49, 0xa5, 0xf9, 0x26, 0x39, 0x39, 0xc, 0x62, 0x9a, 0x5e, 0x47, 0x5c, 0x48, 0xe4, 0x8e, 0xe8, 0x91, 0x61, 0x70, 0xd5, 0xdd, 0x2e, 0x5d}

	reader := bytes.NewReader(ciphertext)
	writer := new(bytes.Buffer)

	err := s.kmsCrypter.Decrypt(writer, reader)
	r.NoError(err)
	r.Equal(plaintext, writer.String())
}

func (s *KMSCrypterTestSuite) Test_Decrypt_previous_DEK_cached() {
	r := s.Require()

	cache, _ := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1000,
		MaxCost:     100,
		BufferItems: 64,
	})

	key := []byte{0xfd, 0xef, 0x2, 0x56, 0x2f, 0xe1, 0xd, 0x35, 0x92, 0x8c, 0x33, 0x58, 0x7d, 0x83, 0xe9, 0x52, 0xd2, 0x98, 0x26, 0xa0, 0xba, 0x4e, 0x64, 0x50, 0x4b, 0xfa, 0xfc, 0xc1, 0x8e, 0xd9, 0x55, 0xe5}

	encryptedKey := []byte{0x4b, 0x61, 0x72, 0x6e, 0x3a, 0x61, 0x77, 0x73, 0x3a, 0x6b, 0x6d, 0x73, 0x3a, 0x65, 0x75, 0x2d, 0x77, 0x65, 0x73, 0x74, 0x2d, 0x32, 0x3a, 0x31, 0x31, 0x31, 0x31, 0x32, 0x32, 0x32, 0x32, 0x33, 0x33, 0x33, 0x33, 0x3a, 0x6b, 0x65, 0x79, 0x2f, 0x62, 0x38, 0x66, 0x61, 0x63, 0x30, 0x34, 0x63, 0x2d, 0x65, 0x64, 0x38, 0x31, 0x2d, 0x34, 0x32, 0x38, 0x33, 0x2d, 0x38, 0x38, 0x35, 0x37, 0x2d, 0x37, 0x62, 0x39, 0x66, 0x63, 0x65, 0x32, 0x35, 0x62, 0x63, 0x33, 0x64, 0x0, 0x0, 0x0, 0x0, 0xfb, 0x25, 0xe9, 0x99, 0xab, 0xde, 0xb8, 0xc4, 0x99, 0xbb, 0x1f, 0x79, 0x45, 0xb3, 0xe2, 0x53, 0x69, 0x65, 0x61, 0xa5, 0xae, 0xaa, 0x2f, 0x3b, 0x36, 0xaf, 0xce, 0xad, 0xfa, 0x4d, 0xc7, 0x42, 0x5, 0x3d, 0xd8, 0xcf, 0xea, 0x13, 0x11, 0xb5, 0x79, 0x87, 0x67, 0x3c, 0x54, 0x98, 0x5d, 0xeb, 0xa6, 0x1e, 0xd9, 0x89, 0xf1, 0x4c, 0x8d, 0x52, 0x65, 0x54, 0xb6, 0xf9}

	r.True(cache.Set(encryptedKey, key, 1))
	cache.Wait()

	cipherBlock, err := aes.NewCipher(key)
	r.NoError(err)
	aesgcm, err := cipher.NewGCM(cipherBlock)
	r.NoError(err)

	kmsCrypter := &KMSCrypter{
		client: s.client,
		keyID:  KmsKeyAlias,
		cache:  cache,
		aesgcm: aesgcm,
	}

	_, ok := kmsCrypter.cache.Get(encryptedKey)
	r.True(ok)

	plaintext := "Hello World"

	ciphertext := []byte{0x8c, 0x4b, 0x61, 0x72, 0x6e, 0x3a, 0x61, 0x77, 0x73, 0x3a, 0x6b, 0x6d, 0x73, 0x3a, 0x65, 0x75, 0x2d, 0x77, 0x65, 0x73, 0x74, 0x2d, 0x32, 0x3a, 0x31, 0x31, 0x31, 0x31, 0x32, 0x32, 0x32, 0x32, 0x33, 0x33, 0x33, 0x33, 0x3a, 0x6b, 0x65, 0x79, 0x2f, 0x62, 0x38, 0x66, 0x61, 0x63, 0x30, 0x34, 0x63, 0x2d, 0x65, 0x64, 0x38, 0x31, 0x2d, 0x34, 0x32, 0x38, 0x33, 0x2d, 0x38, 0x38, 0x35, 0x37, 0x2d, 0x37, 0x62, 0x39, 0x66, 0x63, 0x65, 0x32, 0x35, 0x62, 0x63, 0x33, 0x64, 0x0, 0x0, 0x0, 0x0, 0xfb, 0x25, 0xe9, 0x99, 0xab, 0xde, 0xb8, 0xc4, 0x99, 0xbb, 0x1f, 0x79, 0x45, 0xb3, 0xe2, 0x53, 0x69, 0x65, 0x61, 0xa5, 0xae, 0xaa, 0x2f, 0x3b, 0x36, 0xaf, 0xce, 0xad, 0xfa, 0x4d, 0xc7, 0x42, 0x5, 0x3d, 0xd8, 0xcf, 0xea, 0x13, 0x11, 0xb5, 0x79, 0x87, 0x67, 0x3c, 0x54, 0x98, 0x5d, 0xeb, 0xa6, 0x1e, 0xd9, 0x89, 0xf1, 0x4c, 0x8d, 0x52, 0x65, 0x54, 0xb6, 0xf9, 0x87, 0xd0, 0x9b, 0xc2, 0x5f, 0x7e, 0x64, 0xa, 0xdf, 0x3, 0xb3, 0xea, 0x70, 0xb8, 0x7d, 0xb8, 0x49, 0xa5, 0xf9, 0x26, 0x39, 0x39, 0xc, 0x62, 0x9a, 0x5e, 0x47, 0x5c, 0x48, 0xe4, 0x8e, 0xe8, 0x91, 0x61, 0x70, 0xd5, 0xdd, 0x2e, 0x5d}

	reader := bytes.NewReader(ciphertext)
	writer := new(bytes.Buffer)

	err = kmsCrypter.Decrypt(writer, reader)
	r.NoError(err)
	r.Equal(plaintext, writer.String())
}

func Test_KMSCrypterTestSuite(t *testing.T) {
	suite.Run(t, new(KMSCrypterTestSuite))
}

// These two tests are deliberately not part of the above test suite.
func Test_KMSCrypter_Decrypt_ciphertext_too_short(t *testing.T) {
	key := make([]byte, 32)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	k := &KMSCrypter{aesgcm: gcm}

	buf := new(bytes.Buffer)
	require.NoError(t, binary.Write(buf, binary.LittleEndian, uint8(40)))
	buf.Write(make([]byte, 10)) // 11 bytes total: 1 + 10, insufficient for keyLength 40 + nonce + tag

	err = k.Decrypt(io.Discard, bytes.NewReader(buf.Bytes()))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read ciphertext: minimum length not met")
}

func Test_KMSCrypter_Decrypt_SingleByteDoesNotPanic(t *testing.T) {
	key := make([]byte, 32)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	k := &KMSCrypter{aesgcm: gcm}

	err = k.Decrypt(io.Discard, bytes.NewReader([]byte{0x05}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read ciphertext: minimum length not met")
}

func Test_New_invalid_request_timeout(t *testing.T) {
	_, err := New(context.Background(), getLocalKMSClient(), KmsKeyAlias, WithRequestTimeout(0))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request timeout must be greater than zero")
}

func Test_New_invalid_KMS_decrypt_rate_limit(t *testing.T) {
	_, err := New(context.Background(), getLocalKMSClient(), KmsKeyAlias, WithKMSDecryptRateLimit(0, 1))
	require.Error(t, err)
	_, err = New(context.Background(), getLocalKMSClient(), KmsKeyAlias, WithKMSDecryptRateLimit(1, 0))
	require.Error(t, err)
}

func Test_New_invalid_DEK_cache_config(t *testing.T) {
	_, err := New(context.Background(), getLocalKMSClient(), KmsKeyAlias, WithDEKCacheConfig(ristretto.Config{
		NumCounters: 100,
		MaxCost:     1000,
		BufferItems: 16,
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NumCounters must be >= MaxCost")

	_, err = New(context.Background(), getLocalKMSClient(), KmsKeyAlias, WithDEKCacheConfig(ristretto.Config{
		NumCounters: 10_000,
		MaxCost:     0,
		BufferItems: 16,
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MaxCost must be greater than zero")

	_, err = New(context.Background(), getLocalKMSClient(), KmsKeyAlias, WithDEKCacheConfig(ristretto.Config{
		NumCounters: 10_000,
		MaxCost:     1000,
		BufferItems: 0,
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "BufferItems must be greater than zero")
}

func Test_New_request_timeout_applies_to_GenerateDataKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	client := getTestKMSClient(server.URL)
	_, err := New(context.Background(), client, KmsKeyAlias, WithRequestTimeout(50*time.Millisecond))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to retrieve data key from AWS KMS")
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// dekFromEncryptedBlob returns a deterministic 32-byte AES-256 key derived from the
// KMS ciphertext blob (simulates a unique plaintext DEK per encrypted DEK). Used by
// fakeDEKStub.Decrypt and by tests that seal payloads for a given blob.
func dekFromEncryptedBlob(blob []byte) []byte {
	sum := sha256.Sum256(blob)
	return append([]byte(nil), sum[:]...)
}

// fakeDEKStub implements kmsAPI for unit tests. GenerateDataKey returns a fixed current
// DEK; Decrypt returns a deterministic DEK derived from CiphertextBlob so cache key/value
// mistakes fail AES-GCM Open instead of masking bugs.
type fakeDEKStub struct {
	decryptCalls int
	dek          []byte
	currentEnc   []byte
}

func newFakeDEKStub() *fakeDEKStub {
	dek := make([]byte, 32)
	dek[0] = 0x11
	cur := make([]byte, 140)
	for i := range cur {
		cur[i] = byte(i + 1)
	}
	return &fakeDEKStub{dek: dek, currentEnc: cur}
}

func (f *fakeDEKStub) GenerateDataKey(ctx context.Context, in *kms.GenerateDataKeyInput, opt ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	return &kms.GenerateDataKeyOutput{
		Plaintext:      append([]byte(nil), f.dek...),
		CiphertextBlob: append([]byte(nil), f.currentEnc...),
	}, nil
}

func (f *fakeDEKStub) Decrypt(ctx context.Context, in *kms.DecryptInput, opt ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	f.decryptCalls++
	dek := dekFromEncryptedBlob(in.CiphertextBlob)
	return &kms.DecryptOutput{Plaintext: dek}, nil
}

// stallKMS implements kmsAPI; Decrypt blocks until the request context ends (for timeout tests).
type stallKMS struct {
	dek        []byte
	currentEnc []byte
}

func newStallKMS() *stallKMS {
	dek := make([]byte, 32)
	dek[0] = 0x22
	cur := make([]byte, 140)
	for i := range cur {
		cur[i] = byte(200 + i)
	}
	return &stallKMS{dek: dek, currentEnc: cur}
}

func (s *stallKMS) GenerateDataKey(ctx context.Context, in *kms.GenerateDataKeyInput, opt ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	return &kms.GenerateDataKeyOutput{
		Plaintext:      append([]byte(nil), s.dek...),
		CiphertextBlob: append([]byte(nil), s.currentEnc...),
	}, nil
}

func (s *stallKMS) Decrypt(ctx context.Context, in *kms.DecryptInput, opt ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func testRistretto(t *testing.T) *ristretto.Cache {
	t.Helper()
	c, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 10,
		MaxCost:     1 << 20,
		BufferItems: 64,
	})
	require.NoError(t, err)
	return c
}

func aesGCMDEKFromBlob(t *testing.T, encryptedDEKBLOB []byte) cipher.AEAD {
	t.Helper()
	b, err := aes.NewCipher(dekFromEncryptedBlob(encryptedDEKBLOB))
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(b)
	require.NoError(t, err)
	return gcm
}

func wireKMSCiphertext(t *testing.T, encDEK []byte, nonce []byte, plain []byte, aead cipher.AEAD) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, uint8(len(encDEK)))) //nolint:gosec // test blobs are length 140
	buf.Write(encDEK)
	buf.Write(nonce)
	buf.Write(aead.Seal(nil, nonce, plain, nil))
	return buf.Bytes()
}

func Test_Decrypt_KMS_rate_limit_second_miss(t *testing.T) {
	stub := newFakeDEKStub()
	block, err := aes.NewCipher(stub.dek)
	require.NoError(t, err)
	currentAEAD, err := cipher.NewGCM(block)
	require.NoError(t, err)

	k := &KMSCrypter{
		client:             stub,
		keyID:              KmsKeyAlias,
		encryptedKey:       append([]byte(nil), stub.currentEnc...),
		encryptedKeyLength: 140,
		aesgcm:             currentAEAD,
		cache:              testRistretto(t),
		requestTimeout:     time.Second,
		decryptLimiter:     rate.NewLimiter(rate.Limit(1), 1),
	}

	nonce1 := make([]byte, 12)
	nonce1[11] = 1
	nonce2 := make([]byte, 12)
	nonce2[11] = 2
	plain := []byte("hello")
	alt1 := make([]byte, 140)
	alt1[0] = 0xEE
	alt2 := make([]byte, 140)
	alt2[0] = 0xDD

	gcm1 := aesGCMDEKFromBlob(t, alt1)
	gcm2 := aesGCMDEKFromBlob(t, alt2)

	b1 := wireKMSCiphertext(t, alt1, nonce1, plain, gcm1)
	out := new(bytes.Buffer)
	require.NoError(t, k.Decrypt(out, bytes.NewReader(b1)))
	assert.Equal(t, plain, out.Bytes())
	assert.Equal(t, 1, stub.decryptCalls)

	b2 := wireKMSCiphertext(t, alt2, nonce2, plain, gcm2)
	err = k.Decrypt(new(bytes.Buffer), bytes.NewReader(b2))
	require.Error(t, err)
	require.ErrorIs(t, err, ErrKMSDecryptRateLimited)
	assert.Equal(t, 1, stub.decryptCalls, "second decrypt must not call KMS when rate limited")
}

func Test_Decrypt_KMS_deadline_exceeded(t *testing.T) {
	stub := newStallKMS()
	block, err := aes.NewCipher(stub.dek)
	require.NoError(t, err)
	aeadgcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	k := &KMSCrypter{
		client:             stub,
		keyID:              KmsKeyAlias,
		encryptedKey:       append([]byte(nil), stub.currentEnc...),
		encryptedKeyLength: 140,
		aesgcm:             aeadgcm,
		cache:              testRistretto(t),
		requestTimeout:     10 * time.Millisecond,
	}

	nonce := make([]byte, 12)
	plain := []byte("hello")
	alt := make([]byte, 140)
	alt[0] = 0xCC
	b := wireKMSCiphertext(t, alt, nonce, plain, aeadgcm)
	err = k.Decrypt(new(bytes.Buffer), bytes.NewReader(b))
	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
