package sqlcrypter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_NewEncryptedBytes(t *testing.T) {
	t.Run("nil string", func(t *testing.T) {
		var b []byte
		e := NewEncryptedBytes("")
		assert.Equal(t, b, e.Bytes())
		assert.Nil(t, e)
	})

	t.Run("success", func(t *testing.T) {
		s := "Hello World"
		e := NewEncryptedBytes(s)
		assert.Equal(t, s, e.String())
	})
}

func Test_EncryptedBytes_Scan(t *testing.T) {
	Init(&base64Crypter{})

	t.Run("nil value", func(t *testing.T) {
		e := NewEncryptedBytes("")
		var b []byte
		err := e.Scan(b)
		assert.Nil(t, err)
		assert.Nil(t, e)
	})

	t.Run("not bytes", func(t *testing.T) {
		e := NewEncryptedBytes("")
		err := e.Scan("string, not bytes")
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "failed to read value as bytes")
	})

	t.Run("decrypt", func(t *testing.T) {
		e := &EncryptedBytes{}
		err := e.Scan([]byte("SGVsbG8gV29ybGQ="))
		assert.Nil(t, err)
		assert.Equal(t, "Hello World", e.String())
	})
}

func Test_EncryptedBytes_Value(t *testing.T) {
	Init(&base64Crypter{})

	t.Run("nil value", func(t *testing.T) {
		e := &EncryptedBytes{}
		var b []byte
		d, err := e.Value()
		assert.Nil(t, err)
		assert.Equal(t, b, d)
	})

	t.Run("encrypt", func(t *testing.T) {
		e := NewEncryptedBytes("Hello World")
		d, err := e.Value()
		assert.Nil(t, err)

		b, ok := d.([]byte)
		assert.True(t, ok)
		assert.Equal(t, string(b), "SGVsbG8gV29ybGQ=")
	})
}

func Test_EncryptedBytes_MarshalJSON(t *testing.T) {
	s := "Hello World"
	e := NewEncryptedBytes(s)
	b, err := e.MarshalJSON()
	assert.Nil(t, err)
	assert.Equal(t, "\"Hello World\"", string(b))
}

func Test_EncryptedBytes_UnmarshalJSON(t *testing.T) {
	e := &EncryptedBytes{}
	err := e.UnmarshalJSON([]byte("\"Hello World\""))
	assert.Nil(t, err)
	assert.Equal(t, "Hello World", e.String())
}
