package sqlcrypter

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		assert.Equal(t, s, e.Plaintext())
	})

	t.Run("String redacts", func(t *testing.T) {
		e := NewEncryptedBytes("super secret")
		assert.Equal(t, "[REDACTED]", e.String())
	})
}

func Test_EncryptedBytes_String(t *testing.T) {
	secret := "do-not-leak-this-credential"
	e := NewEncryptedBytes(secret)

	out := fmt.Sprint(e)
	assert.NotContains(t, out, secret, "formatted output must not contain plaintext")
	assert.Equal(t, "[REDACTED]", out)
}

func Test_EncryptedBytes_Plaintext(t *testing.T) {
	tests := []struct {
		name   string
		value  func() EncryptedBytes
		want   string
		nilBuf bool
	}{
		{
			name:   "empty",
			value:  func() EncryptedBytes { return NewEncryptedBytes("") },
			want:   "",
			nilBuf: true,
		},
		{
			name:  "non_empty",
			value: func() EncryptedBytes { return NewEncryptedBytes("Hello World") },
			want:  "Hello World",
		},
		{
			name:  "unicode",
			value: func() EncryptedBytes { return NewEncryptedBytes("你好世界") },
			want:  "你好世界",
		},
		{
			name: "nil_slice",
			value: func() EncryptedBytes {
				var e EncryptedBytes
				return e
			},
			want:   "",
			nilBuf: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := tt.value()
			assert.Equal(t, tt.want, e.Plaintext())
			if tt.nilBuf {
				assert.Nil(t, []byte(e))
			}
		})
	}
}

func Test_EncryptedBytes_Bytes(t *testing.T) {
	tests := []struct {
		name        string
		value       func() EncryptedBytes
		want        []byte
		nilBuf      bool
		mutateFirst bool // mutating returned slice updates backing EncryptedBytes
		afterMutate string
	}{
		{
			name:   "empty",
			value:  func() EncryptedBytes { return NewEncryptedBytes("") },
			want:   nil,
			nilBuf: true,
		},
		{
			name:        "non_empty",
			value:       func() EncryptedBytes { return NewEncryptedBytes("Hello World") },
			want:        []byte("Hello World"),
			mutateFirst: true,
			afterMutate: "Jello World",
		},
		{
			name:  "unicode",
			value: func() EncryptedBytes { return NewEncryptedBytes("你好世界") },
			want:  []byte("你好世界"),
		},
		{
			name: "nil_slice",
			value: func() EncryptedBytes {
				var e EncryptedBytes
				return e
			},
			want:   nil,
			nilBuf: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := tt.value()
			got := e.Bytes()
			assert.Equal(t, tt.want, got)
			if tt.nilBuf {
				assert.Nil(t, got)
			}
			if tt.mutateFirst {
				require.NotEmpty(t, got)
				got[0] = 'J'
				assert.Equal(t, tt.afterMutate, e.Plaintext())
			}
		})
	}
}

func Test_EncryptedBytes_GormDataType(t *testing.T) {
	tests := []struct {
		name  string
		value func() EncryptedBytes
	}{
		{
			name:  "with_plaintext",
			value: func() EncryptedBytes { return NewEncryptedBytes("secret") },
		},
		{
			name:  "empty_constructor",
			value: func() EncryptedBytes { return NewEncryptedBytes("") },
		},
		{
			name: "nil_slice",
			value: func() EncryptedBytes {
				var e EncryptedBytes
				return e
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := tt.value()
			p := &e
			assert.Equal(t, "encryptedbytes", p.GormDataType())
		})
	}
}

func Test_EncryptedBytes_Scan(t *testing.T) {
	Init(&base64Crypter{})

	t.Run("nil value", func(t *testing.T) {
		e := NewEncryptedBytes("")
		var b []byte
		err := e.Scan(b)
		require.NoError(t, err)
		assert.Nil(t, e)
	})

	t.Run("not bytes", func(t *testing.T) {
		e := NewEncryptedBytes("")
		err := e.Scan("string, not bytes")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read value as bytes")
	})

	t.Run("decrypt", func(t *testing.T) {
		e := &EncryptedBytes{}
		err := e.Scan([]byte("SGVsbG8gV29ybGQ="))
		require.NoError(t, err)
		assert.Equal(t, "Hello World", e.Plaintext())
	})
}

func Test_EncryptedBytes_Value(t *testing.T) {
	Init(&base64Crypter{})

	t.Run("nil value", func(t *testing.T) {
		e := &EncryptedBytes{}
		var b []byte
		d, err := e.Value()
		require.NoError(t, err)
		assert.Equal(t, b, d)
	})

	t.Run("encrypt", func(t *testing.T) {
		e := NewEncryptedBytes("Hello World")
		d, err := e.Value()
		require.NoError(t, err)

		b, ok := d.([]byte)
		assert.True(t, ok)
		assert.Equal(t, "SGVsbG8gV29ybGQ=", string(b))
	})
}

func Test_EncryptedBytes_MarshalJSON(t *testing.T) {
	Init(&base64Crypter{})

	m := map[string]EncryptedBytes{
		"v": NewEncryptedBytes("Hello World"),
	}

	b, err := json.Marshal(m)
	require.NoError(t, err)
	assert.JSONEq(t, `{"v":"U0dWc2JHOGdWMjl5YkdRPQ=="}`, string(b))
}

func Test_EncryptedBytes_UnmarshalJSON(t *testing.T) {
	Init(&base64Crypter{})

	data := []byte(`{"secret":"U0dWc2JHOGdWMjl5YkdRPQ=="}`)

	type Example struct {
		Secret EncryptedBytes
	}

	var e Example

	err := json.Unmarshal(data, &e)
	require.NoError(t, err)
	assert.Equal(t, "Hello World", e.Secret.Plaintext())
}
