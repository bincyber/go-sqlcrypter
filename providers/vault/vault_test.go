package vault

import (
	"bytes"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
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

func (s *VaultCrypterTestSuite) SetupTest() {
	s.client = getVaultClient()

	vaultCrypter, err := New(s.client, transitMount, transitKey)
	assert.Nil(s.T(), err)
	s.vaultCrypter = vaultCrypter
}

func (s *VaultCrypterTestSuite) Test_New() {}

func (s *VaultCrypterTestSuite) Test_New_nil_client() {
	r := s.Require()

	_, err := New(nil, transitMount, transitKey)
	r.NotNil(err)
	r.Contains(err.Error(), "vaultapi.Client cannot be nil")
}

func (s *VaultCrypterTestSuite) Test_New_nil_mount() {
	r := s.Require()

	client := getVaultClient()

	_, err := New(client, "", transitKey)
	r.NotNil(err)
	r.Contains(err.Error(), "mount cannot be nil")
}

func (s *VaultCrypterTestSuite) Test_New_nil_key() {
	r := s.Require()

	client := getVaultClient()

	_, err := New(client, transitMount, "")
	r.NotNil(err)
	r.Contains(err.Error(), "key cannot be nil")
}

func (s *VaultCrypterTestSuite) Test_getEncryptEndpoint() {
	r := s.Require()

	vaultCrypter := VaultCrypter{
		mount: transitMount,
		key:   transitKey,
	}

	r.Equal(vaultCrypter.getEncryptEndpoint(), "transit/encrypt/go-sqlcrypter")
}

func (s *VaultCrypterTestSuite) Test_getDecryptEndpoint() {
	r := s.Require()

	vaultCrypter := VaultCrypter{
		mount: transitMount,
		key:   transitKey,
	}

	r.Equal(vaultCrypter.getDecryptEndpoint(), "transit/decrypt/go-sqlcrypter")
}

func (s *VaultCrypterTestSuite) Test_Encrypt() {
	r := s.Require()

	plaintext := "Hello World"

	reader := bytes.NewBufferString(plaintext)
	writer := new(bytes.Buffer)

	err := s.vaultCrypter.Encrypt(writer, reader)
	r.Nil(err)

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
	r.NotNil(err)
	r.Contains(err.Error(), "failed to encrypt data using transit secrets engine")
}

func (s *VaultCrypterTestSuite) Test_Decrypt() {
	r := s.Require()

	plaintext := "Hello World"

	reader := bytes.NewBufferString(plaintext)
	writer := new(bytes.Buffer)

	err := s.vaultCrypter.Encrypt(writer, reader)
	r.Nil(err)

	reader = new(bytes.Buffer)

	err = s.vaultCrypter.Decrypt(reader, writer)
	r.Nil(err)
	r.Contains(reader.String(), plaintext)
}

func (s *VaultCrypterTestSuite) Test_Decrypt_err() {
	r := s.Require()

	ciphertext := "vault:v1:SGVsbG8gV29ybGQ="

	reader := bytes.NewBufferString(ciphertext)
	writer := new(bytes.Buffer)

	err := s.vaultCrypter.Decrypt(writer, reader)
	r.NotNil(err)
	r.Contains(err.Error(), "failed to decrypt data using transit secrets engine")
}

func Test_KMSCrypterTestSuite(t *testing.T) {
	suite.Run(t, new(VaultCrypterTestSuite))
}
