package sqlcrypter

import "errors"

var (
	// ErrInitWithNil indicates that Init() has been called with a nil Crypterer.
	ErrInitWithNil = errors.New("sqlcrypter: Init() called with nil crypter")

	// ErrCrypterNotInitialized indicates that Init() has not been called
	// with a valid Crypterer before Encrypt()/Decrypt() usage.
	ErrCrypterNotInitialized = errors.New("sqlcrypter: crypter is not initialized")
)
