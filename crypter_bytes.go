package sqlcrypter

import "bytes"

// encryptPlaintextBytes encrypts plaintext and returns ciphertext bytes.
func encryptPlaintextBytes(plaintext []byte) ([]byte, error) {
	reader := bytes.NewReader(plaintext)
	writer := new(bytes.Buffer)
	if err := Encrypt(writer, reader); err != nil {
		return nil, err
	}
	ct := writer.Bytes()
	// Avoid returning a nil []byte slice: database/sql and JSON callers treat
	// nil []byte as NULL/absent; NullEncryptedBytes needs a non-nil ciphertext
	// for encrypted-empty plaintext (distinct from SQL NULL).
	if ct == nil {
		ct = []byte{}
	}
	return ct, nil
}

// decryptCiphertextBytes decrypts ciphertext into plaintext bytes.
func decryptCiphertextBytes(ciphertext []byte) (EncryptedBytes, error) {
	reader := bytes.NewReader(ciphertext)
	writer := new(bytes.Buffer)
	if err := Decrypt(writer, reader); err != nil {
		return nil, err
	}
	return EncryptedBytes(writer.Bytes()), nil
}
