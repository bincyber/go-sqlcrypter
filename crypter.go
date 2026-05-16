package sqlcrypter

import (
	"io"
	"sync"
)

var (
	// crypter is the Crypterer used to encrypt and decrypt.
	// This can only be set once by calling Init().
	crypter Crypterer

	// once ensures that Init() cannot be called more than once.
	once sync.Once
)

type Crypterer interface {
	Encrypt(w io.Writer, r io.Reader) error
	Decrypt(w io.Writer, r io.Reader) error
}

// Init sets the encryption provider used by Encrypt() and Decrypt()
// and can only ever be called once. Repeated calls have no effect.
//
// An errors is returned if the Crypter is nil, so that encryption does
// not get silently disabled for the lifetime of the process.
func Init(c Crypterer) error {
	if c == nil {
		return ErrInitWithNil
	}

	once.Do(func() {
		crypter = c
	})

	return nil
}

// Encrypt reads plaintext from an io.Reader
// and writes ciphertext to an io.Writer.
func Encrypt(w io.Writer, r io.Reader) error {
	if crypter == nil {
		return ErrCrypterNotInitialized
	}

	return crypter.Encrypt(w, r)
}

// Decrypt reads ciphertext from an io.Reader
// and writes plaintext to an io.Writer.
func Decrypt(w io.Writer, r io.Reader) error {
	if crypter == nil {
		return ErrCrypterNotInitialized
	}

	return crypter.Decrypt(w, r)
}
