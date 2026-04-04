package sqlcrypter

import "errors"

// ErrCrypterNotInitialized indicates that Init() has not been called
// with a valid Crypterer before Encrypt()/Decrypt() usage.
var ErrCrypterNotInitialized = errors.New("sqlcrypter: crypter is not initialized")
