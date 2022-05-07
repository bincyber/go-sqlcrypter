package aesgcm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"io"

	"github.com/pkg/errors"

	"github.com/bincyber/go-sqlcrypter"
)

// AESCrypter is an implementation of the Crypterer interface using
// 256-bit AES in Galeious Counter Mode with support for key rotation.
type AESCrypter struct {
	// current is AES GCM block cipher used to encrypt any new data
	// using the current data encryption key.
	current cipher.AEAD

	// previous is is AES GCM block cipher used to decrypt old data
	// using the previous data encryption key.
	previous cipher.AEAD
}

// New initializes the AES GCM crypter with the provided data encryption key (DEK).
// To support key rotation, a previous DEK can optionally be provided. If the
// previous DEK is set, it is only used for decryption. Any new data is encrypted
// with the current DEK.
func New(key []byte, previousKey []byte) (sqlcrypter.Crypterer, error) {
	if len(key) != 32 {
		return nil, errors.Wrap(aes.KeySizeError(len(key)), "DEK is invalid")
	}

	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	current, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create GCM wrapped block cipher")
	}

	var previous cipher.AEAD
	if previousKey != nil {
		if len(previousKey) != 32 {
			return nil, errors.Wrap(aes.KeySizeError(len(previousKey)), "previous DEK is invalid")
		}

		cipherBlock, err := aes.NewCipher(previousKey)
		if err != nil {
			return nil, err
		}

		previous, err = cipher.NewGCM(cipherBlock)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create GCM wrapped block cipher")
		}
	}

	return &AESCrypter{
		current:  current,
		previous: previous,
	}, nil
}

// Encrypt encrypts plaintext to ciphertext using the current DEK.
func (a *AESCrypter) Encrypt(w io.Writer, r io.Reader) error {
	src := new(bytes.Buffer)
	_, err := src.ReadFrom(r)
	if err != nil {
		return errors.Wrap(err, "failed to read from io.Reader")
	}

	nonce, err := sqlcrypter.GenerateBytes(a.current.NonceSize())
	if err != nil {
		return errors.Wrap(err, "failed to generate 12-byte random nonce")
	}

	ciphertext := a.current.Seal(nil, nonce, src.Bytes(), nil)

	// First 12 bytes will be the nonce, followed by the ciphertext
	w.Write(nonce)
	w.Write(ciphertext)

	return nil
}

// Decrypt decrypts ciphertext to plaintext. It first attempts to decrypt
// using the previous DEK if specified, followed by the current DEK.
func (a *AESCrypter) Decrypt(w io.Writer, r io.Reader) error {
	src := new(bytes.Buffer)
	n, err := src.ReadFrom(r)
	if err != nil {
		return errors.Wrap(err, "failed to read from io.Reader")
	}

	// First 12 bytes is the nonce, followed by the ciphertext
	nonce := src.Next(12)
	ciphertext := src.Next(int(n))

	// First attempt to decrypt using previous DEK if specified
	var attempted bool
	if a.previous != nil {
		if plaintext, err := a.previous.Open(nil, nonce, ciphertext, nil); err == nil {
			w.Write(plaintext)
			return nil
		}

		attempted = true
	}

	// Decrypt using the current DEK
	plaintext, err := a.current.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		if attempted {
			return errors.Wrap(err, "failed to decrypt ciphertext using current and previous DEK")
		}

		return errors.Wrap(err, "failed to decrypt ciphertext using current DEK")
	}

	w.Write(plaintext)

	return nil
}

var _ sqlcrypter.Crypterer = (*AESCrypter)(nil)
