package vault

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"path/filepath"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/pkg/errors"

	"github.com/bincyber/go-sqlcrypter"
)

// VaultCrypter is an implementation of the Crypterer interface
// using HashiCorp Vault's Transit secrets engine.
type VaultCrypter struct {
	client *vaultapi.Client
	mount  string
	key    string
}

// New creates a new Vault crypter configured to encrypt data using the
// Transit secrets engine at the specified mount path and key. The latest
// version of the key is always used to encrypt new data.
// Convergent Encryption is not supported.
func New(client *vaultapi.Client, mount, key string) (sqlcrypter.Crypterer, error) {
	if client == nil {
		return nil, fmt.Errorf("failed to create VaultCrypter. Error: vaultapi.Client cannot be nil")
	}

	if mount == "" {
		return nil, fmt.Errorf("failed to create VaultCrypter. Error: mount cannot be nil")
	}

	if key == "" {
		return nil, fmt.Errorf("failed to create VaultCrypter. Error: key cannot be nil")
	}

	v := &VaultCrypter{
		client: client,
		mount:  mount,
		key:    key,
	}

	return v, nil
}

func (v *VaultCrypter) getEncryptEndpoint() string {
	return filepath.Join(v.mount, "encrypt", v.key)
}

func (v *VaultCrypter) getDecryptEndpoint() string {
	return filepath.Join(v.mount, "decrypt", v.key)
}

// Encrypt encrypts plaintext to ciphertext using the Transit secret engine's
// Encrypt endpoint.
//
// See: https://www.vaultproject.io/api-docs/secret/transit#encrypt-data
func (v *VaultCrypter) Encrypt(w io.Writer, r io.Reader) error {
	src := new(bytes.Buffer)
	_, err := src.ReadFrom(r)
	if err != nil {
		return errors.Wrap(err, "failed to read from io.Reader")
	}

	// Plaintext must be base64-encoded
	p := map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(src.Bytes()),
	}

	resp, err := v.client.Logical().Write(v.getEncryptEndpoint(), p)
	if err != nil {
		return errors.Wrapf(err, "failed to encrypt data using transit secrets engine: mount %q and key %q", v.mount, v.key)
	}

	data, ok := resp.Data["ciphertext"]
	if !ok {
		return errors.Wrap(err, "failed to extract ciphertext from Vault's response")
	}

	ciphertext, ok := data.(string)
	if !ok {
		return errors.Wrap(err, "failed to convert ciphertext to string")
	}

	w.Write([]byte(ciphertext))

	return nil
}

// Decrypt decrypts ciphertext to plaintext using the Transit secret engine's
// Decrypt endpoint.
//
// See: https://www.vaultproject.io/api-docs/secret/transit#decrypt-data
func (v *VaultCrypter) Decrypt(w io.Writer, r io.Reader) error {
	src := new(bytes.Buffer)
	_, err := src.ReadFrom(r)
	if err != nil {
		return errors.Wrap(err, "failed to read from io.Reader")
	}

	p := map[string]interface{}{
		"ciphertext": src.String(),
	}

	resp, err := v.client.Logical().Write(v.getDecryptEndpoint(), p)
	if err != nil {
		return errors.Wrapf(err, "failed to decrypt data using transit secrets engine: mount %q and key %q", v.mount, v.key)
	}

	data, ok := resp.Data["plaintext"]
	if !ok {
		return errors.Wrap(err, "failed to extract plaintext from Vault's response")
	}

	b64Plaintext, ok := data.(string)
	if !ok {
		return errors.Wrap(err, "failed to convert plaintext to string")
	}

	// Plaintext is base64 encoded and must be decoded
	plaintext, err := base64.StdEncoding.DecodeString(b64Plaintext)
	if err != nil {
		return errors.Wrap(err, "failed to base64 decode plaintext")
	}

	w.Write(plaintext)

	return nil
}

var _ sqlcrypter.Crypterer = (*VaultCrypter)(nil)
