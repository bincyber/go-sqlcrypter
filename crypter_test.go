package sqlcrypter

import (
	"bytes"
	"encoding/base64"
	"io"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

// base64Crypter exists only for test purposes
type base64Crypter struct{}

// Encrypt aka Encode
func (c *base64Crypter) Encrypt(w io.Writer, r io.Reader) error {
	src := new(bytes.Buffer)
	n, err := src.ReadFrom(r)
	if err != nil {
		return errors.Wrap(err, "failed to read from io.Reader")
	}

	dst := make([]byte, base64.StdEncoding.EncodedLen(int(n)))

	base64.StdEncoding.Encode(dst, src.Bytes())

	if _, err := w.Write(dst); err != nil {
		return errors.Wrap(err, "failed to write to io.Writer")
	}

	return nil
}

// Decrypt aka Decode
func (c *base64Crypter) Decrypt(w io.Writer, r io.Reader) error {
	src := new(bytes.Buffer)
	n, err := src.ReadFrom(r)
	if err != nil {
		return errors.Wrap(err, "failed to read from io.Reader")
	}

	dst := make([]byte, base64.StdEncoding.DecodedLen(int(n)))

	l, err := base64.StdEncoding.Decode(dst, src.Bytes())
	if err != nil {
		return errors.Wrap(err, "failed to base64 decode contents of io.Reader")
	}

	if _, err := w.Write(dst[:l]); err != nil {
		return errors.Wrap(err, "failed to write to io.Writer")
	}

	return nil
}

var _ Crypterer = (*base64Crypter)(nil)

func Test_Set(t *testing.T) {
	c := &base64Crypter{}
	Init(c)

	assert.Equal(t, crypter, c)
}

func Test_Encrypt(t *testing.T) {
	crypter = &base64Crypter{}

	plaintext := "Hello World"
	ciphertext := "SGVsbG8gV29ybGQ="

	reader := bytes.NewBufferString(plaintext)
	writer := new(bytes.Buffer)

	err := Encrypt(writer, reader)
	assert.Nil(t, err)
	assert.Equal(t, writer.String(), ciphertext)
}

func Test_Decrypt(t *testing.T) {
	crypter = &base64Crypter{}

	ciphertext := "SGVsbG8gV29ybGQ="
	plaintext := "Hello World"

	reader := bytes.NewBufferString(ciphertext)
	writer := new(bytes.Buffer)

	err := Decrypt(writer, reader)
	assert.Nil(t, err)
	assert.Equal(t, writer.String(), plaintext)
}
