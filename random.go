package sqlcrypter

import (
	"crypto/rand"
	"io"
)

// GenerateBytes generates random bytes of n length.
func GenerateBytes(n int) ([]byte, error) {
	nonce := make([]byte, n)

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return nonce, nil
}
