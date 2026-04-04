package vault

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/bincyber/go-sqlcrypter"
)

const (
	transitMount = "transit"
	transitKey   = "go-sqlcrypter"
)

// getVaultClient returns a Vault client configured to
// make requests to a locally running Vault server.
func getVaultClient() *vaultapi.Client {
	client, _ := vaultapi.NewClient(&vaultapi.Config{
		Address: "http://localhost:8200",
	})

	client.SetToken("vaultroottoken")

	return client
}

type VaultCrypterTestSuite struct {
	suite.Suite
	client       *vaultapi.Client
	vaultCrypter sqlcrypter.Crypterer
}

func newTestVaultClient(t *testing.T, h http.HandlerFunc) (*vaultapi.Client, func()) {
	t.Helper()

	server := httptest.NewServer(h)

	client, err := vaultapi.NewClient(&vaultapi.Config{
		Address: server.URL,
	})
	require.NoError(t, err)

	return client, server.Close
}

func (s *VaultCrypterTestSuite) SetupTest() {
	s.client = getVaultClient()

	vaultCrypter, err := New(s.client, transitMount, transitKey)
	s.Require().NoError(err)
	s.vaultCrypter = vaultCrypter
}

func (s *VaultCrypterTestSuite) Test_New() {}

func (s *VaultCrypterTestSuite) Test_New_nil_client() {
	r := s.Require()

	_, err := New(nil, transitMount, transitKey)
	r.Error(err)
	r.Contains(err.Error(), "vaultapi.Client cannot be nil")
}

func (s *VaultCrypterTestSuite) Test_New_nil_mount() {
	r := s.Require()

	client := getVaultClient()

	_, err := New(client, "", transitKey)
	r.Error(err)
	r.Contains(err.Error(), "mount cannot be nil")
}

func (s *VaultCrypterTestSuite) Test_New_nil_key() {
	r := s.Require()

	client := getVaultClient()

	_, err := New(client, transitMount, "")
	r.Error(err)
	r.Contains(err.Error(), "key cannot be nil")
}

func (s *VaultCrypterTestSuite) Test_getEncryptEndpoint() {
	r := s.Require()

	vaultCrypter := VaultCrypter{
		mount: transitMount,
		key:   transitKey,
	}

	r.Equal("transit/encrypt/go-sqlcrypter", vaultCrypter.getEncryptEndpoint())
}

func (s *VaultCrypterTestSuite) Test_getDecryptEndpoint() {
	r := s.Require()

	vaultCrypter := VaultCrypter{
		mount: transitMount,
		key:   transitKey,
	}

	r.Equal("transit/decrypt/go-sqlcrypter", vaultCrypter.getDecryptEndpoint())
}

func (s *VaultCrypterTestSuite) Test_Encrypt() {
	r := s.Require()

	plaintext := "Hello World"

	reader := bytes.NewBufferString(plaintext)
	writer := new(bytes.Buffer)

	err := s.vaultCrypter.Encrypt(writer, reader)
	r.NoError(err)

	r.Contains(writer.String(), "vault:v1")
}

func (s *VaultCrypterTestSuite) Test_Encrypt_err() {
	r := s.Require()

	client, _ := vaultapi.NewClient(&vaultapi.Config{
		Address: "http://localhost:8200",
	})

	vaultCrypter := VaultCrypter{
		client: client,
		mount:  transitMount,
		key:    transitKey,
	}

	plaintext := "Hello World"

	reader := bytes.NewBufferString(plaintext)
	writer := new(bytes.Buffer)

	err := vaultCrypter.Encrypt(writer, reader)
	r.Error(err)
	r.Contains(err.Error(), "failed to encrypt data using transit secrets engine")
}

func (s *VaultCrypterTestSuite) Test_Decrypt() {
	r := s.Require()

	plaintext := "Hello World"

	reader := bytes.NewBufferString(plaintext)
	writer := new(bytes.Buffer)

	err := s.vaultCrypter.Encrypt(writer, reader)
	r.NoError(err)

	reader = new(bytes.Buffer)

	err = s.vaultCrypter.Decrypt(reader, writer)
	r.NoError(err)
	r.Contains(reader.String(), plaintext)
}

func (s *VaultCrypterTestSuite) Test_Decrypt_err() {
	r := s.Require()

	ciphertext := "vault:v1:SGVsbG8gV29ybGQ="

	reader := bytes.NewBufferString(ciphertext)
	writer := new(bytes.Buffer)

	err := s.vaultCrypter.Decrypt(writer, reader)
	r.Error(err)
	r.Contains(err.Error(), "failed to decrypt data using transit secrets engine")
}

func Test_Encrypt_ResponseMissingCiphertext(t *testing.T) {
	client, closeServer := newTestVaultClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	})
	defer closeServer()

	crypter, err := New(client, transitMount, transitKey)
	require.NoError(t, err)

	writer := new(bytes.Buffer)
	reader := bytes.NewBufferString("Hello World")

	err = crypter.Encrypt(writer, reader)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to extract ciphertext from Vault's response")
}

func Test_Encrypt_ResponseCiphertextNotString(t *testing.T) {
	client, closeServer := newTestVaultClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"ciphertext":123}}`))
	})
	defer closeServer()

	crypter, err := New(client, transitMount, transitKey)
	require.NoError(t, err)

	writer := new(bytes.Buffer)
	reader := bytes.NewBufferString("Hello World")

	err = crypter.Encrypt(writer, reader)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to convert ciphertext to string")
}

func Test_Decrypt_ResponseMissingPlaintext(t *testing.T) {
	client, closeServer := newTestVaultClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	})
	defer closeServer()

	crypter, err := New(client, transitMount, transitKey)
	require.NoError(t, err)

	writer := new(bytes.Buffer)
	reader := bytes.NewBufferString("vault:v1:some-ciphertext")

	err = crypter.Decrypt(writer, reader)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to extract plaintext from Vault's response")
}

func Test_Decrypt_ResponsePlaintextNotString(t *testing.T) {
	client, closeServer := newTestVaultClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"plaintext":123}}`))
	})
	defer closeServer()

	crypter, err := New(client, transitMount, transitKey)
	require.NoError(t, err)

	writer := new(bytes.Buffer)
	reader := bytes.NewBufferString("vault:v1:some-ciphertext")

	err = crypter.Decrypt(writer, reader)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to convert plaintext to string")
}

func Test_VaultCrypterTestSuite(t *testing.T) {
	suite.Run(t, new(VaultCrypterTestSuite))
}
