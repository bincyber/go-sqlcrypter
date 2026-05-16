package aesgcm

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bincyber/go-sqlcrypter"
)

func Test_New(t *testing.T) {
	t.Run("invalid key length", func(t *testing.T) {
		key, _ := sqlcrypter.GenerateBytes(16)

		_, err := New(key, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "DEK is invalid")
	})

	t.Run("current key", func(t *testing.T) {
		key, _ := sqlcrypter.GenerateBytes(32)

		aesCrypter, err := New(key, nil)
		require.NoError(t, err)
		assert.IsType(t, &AESCrypter{}, aesCrypter)
	})

	t.Run("invalid previous key length", func(t *testing.T) {
		current, _ := sqlcrypter.GenerateBytes(32)
		previous := []byte("2819b0fcd8bfa185bd724fb5")

		_, err := New(current, previous)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "previous DEK is invalid")
	})

	t.Run("both keys", func(t *testing.T) {
		current, _ := sqlcrypter.GenerateBytes(32)
		previous, _ := sqlcrypter.GenerateBytes(32)

		aesCrypter, err := New(current, previous)
		require.NoError(t, err)
		assert.IsType(t, &AESCrypter{}, aesCrypter)
	})
}

func Test_AESCryptor_Encrypt(t *testing.T) {
	key := []byte("aa6df350c6164fe8a674864fd1204fe9")

	plaintext := "Hello World"

	reader := bytes.NewBufferString(plaintext)
	writer := new(bytes.Buffer)

	a, _ := New(key, nil)

	err := a.Encrypt(writer, reader)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, writer.String())

	t.Run("err", func(t *testing.T) {
		current, _ := sqlcrypter.GenerateBytes(32)
		previous, _ := sqlcrypter.GenerateBytes(32)

		aesCrypter, err := New(current, previous)
		require.NoError(t, err)
		assert.IsType(t, &AESCrypter{}, aesCrypter)
	})
}

func Test_AESCryptor_Decrypt(t *testing.T) {
	key := []byte("aa6df350c6164fe8a674864fd1204fe9")

	plaintext := "Hello World"

	// encrypted "Hello World" as bytes
	ciphertext := []byte{21, 233, 48, 137, 56, 251, 145, 11, 56, 123, 233, 232, 122, 17, 207, 165, 44, 60, 21, 17, 115, 141, 218, 29, 153, 53, 177, 173, 4, 210, 243, 228, 78, 218, 146, 182, 78, 175, 33}

	t.Run("decrypt error", func(t *testing.T) {
		a, _ := New(key, nil)

		reader := bytes.NewReader([]byte("invalid ciphertext goes here"))
		writer := new(bytes.Buffer)

		err := a.Decrypt(writer, reader)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt ciphertext using current DEK")
	})

	t.Run("decrypt error both keys", func(t *testing.T) {
		previousKey, _ := sqlcrypter.GenerateBytes(32)

		a, _ := New(key, previousKey)

		reader := bytes.NewReader([]byte("invalid ciphertext goes here"))
		writer := new(bytes.Buffer)

		err := a.Decrypt(writer, reader)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt ciphertext using current and previous DEK")
	})

	t.Run("no previous key", func(t *testing.T) {
		a, _ := New(key, nil)

		reader := bytes.NewReader(ciphertext)
		writer := new(bytes.Buffer)

		err := a.Decrypt(writer, reader)
		require.NoError(t, err)
		assert.Equal(t, plaintext, writer.String())
	})

	t.Run("decrypt single byte does not panic", func(t *testing.T) {
		a, err := New(key, nil)
		require.NoError(t, err)

		reader := bytes.NewReader([]byte{0x01})
		writer := new(bytes.Buffer)

		err = a.Decrypt(writer, reader)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read ciphertext: minimum length not met")
	})

	t.Run("decrypt twenty seven bytes does not panic", func(t *testing.T) {
		a, err := New(key, nil)
		require.NoError(t, err)

		// 12-byte nonce + 15 bytes ciphertext/tag (short of 16-byte GCM tag)
		buf := make([]byte, 27)
		reader := bytes.NewReader(buf)
		writer := new(bytes.Buffer)

		err = a.Decrypt(writer, reader)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read ciphertext: minimum length not met")
	})

	t.Run("decrypt with previous key", func(t *testing.T) {
		key := []byte("e4d274d893b4d35e7c54b7947f6b348b")
		previousKey := []byte("aa6df350c6164fe8a674864fd1204fe9")

		// Hello World as encrypted bytes
		ciphertext := []byte{21, 233, 48, 137, 56, 251, 145, 11, 56, 123, 233, 232, 122, 17, 207, 165, 44, 60, 21, 17, 115, 141, 218, 29, 153, 53, 177, 173, 4, 210, 243, 228, 78, 218, 146, 182, 78, 175, 33}

		plaintext := "Hello World"

		reader := bytes.NewReader(ciphertext)
		writer := new(bytes.Buffer)

		a, _ := New(key, previousKey)

		err := a.Decrypt(writer, reader)
		require.NoError(t, err)
		assert.Equal(t, plaintext, writer.String())
	})

	t.Run("decrypt with current key", func(t *testing.T) {
		key := []byte("aa6df350c6164fe8a674864fd1204fe9")
		previousKey := []byte("e4d274d893b4d35e7c54b7947f6b348b")

		// Hello World as encrypted bytes
		ciphertext := []byte{21, 233, 48, 137, 56, 251, 145, 11, 56, 123, 233, 232, 122, 17, 207, 165, 44, 60, 21, 17, 115, 141, 218, 29, 153, 53, 177, 173, 4, 210, 243, 228, 78, 218, 146, 182, 78, 175, 33}

		plaintext := "Hello World"

		reader := bytes.NewReader(ciphertext)
		writer := new(bytes.Buffer)

		a, _ := New(key, previousKey)

		err := a.Decrypt(writer, reader)
		require.NoError(t, err)
		assert.Equal(t, plaintext, writer.String())
	})
}

func Test_AESCrypter_EncryptDecrypt_uninitialized(t *testing.T) {
	t.Run("zero struct", func(t *testing.T) {
		a := &AESCrypter{}

		err := a.Encrypt(io.Discard, bytes.NewReader([]byte("x")))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "AES-GCM was not initialized")

		err = a.Decrypt(io.Discard, bytes.NewReader(make([]byte, 32)))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "AES-GCM was not initialized")
	})
}
