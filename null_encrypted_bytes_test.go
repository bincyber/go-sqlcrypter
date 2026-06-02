package sqlcrypter

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func testInitCrypter(t *testing.T) {
	t.Helper()
	require.NoError(t, Init(&base64Crypter{}))
}

func TestNewNullEncryptedBytes(t *testing.T) {
	testInitCrypter(t)

	n := NewNullEncryptedBytes("hello")
	assert.True(t, n.Valid)
	assert.Equal(t, "hello", n.Plaintext())
	assert.NotNil(t, n.Bytes())

	empty := NewNullEncryptedBytes("")
	assert.True(t, empty.Valid)
	assert.Empty(t, empty.Plaintext())
	assert.Empty(t, empty.Bytes())
	assert.NotNil(t, empty.Bytes())
}

func TestNullEncryptedBytesNull(t *testing.T) {
	testInitCrypter(t)

	n := NullEncryptedBytesNull()
	assert.False(t, n.Valid)
	assert.Empty(t, n.Plaintext())
	assert.Nil(t, n.Bytes())
}

func TestNullEncryptedBytes_Scan(t *testing.T) {
	testInitCrypter(t)

	tests := []struct {
		name      string
		value     any
		wantValid bool
		wantPlain string
		wantErr   bool
	}{
		{name: "untyped_nil", value: nil, wantValid: false, wantPlain: ""},
		{name: "typed_nil_bytes", value: []byte(nil), wantValid: false, wantPlain: ""},
		{
			name:      "ciphertext",
			value:     []byte("SGVsbG8gV29ybGQ="),
			wantValid: true,
			wantPlain: "Hello World",
		},
		{name: "wrong_type", value: "not-bytes", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var n NullEncryptedBytes
			err := n.Scan(tt.value)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantValid, n.Valid)
			assert.Equal(t, tt.wantPlain, n.Plaintext())
		})
	}
}

func TestNullEncryptedBytes_Value(t *testing.T) {
	testInitCrypter(t)

	t.Run("invalid_is_null", func(t *testing.T) {
		n := NullEncryptedBytesNull()
		v, err := n.Value()
		require.NoError(t, err)
		assert.Nil(t, v)
	})

	t.Run("valid_empty_encrypts", func(t *testing.T) {
		n := NewNullEncryptedBytes("")
		v, err := n.Value()
		require.NoError(t, err)
		b, ok := v.([]byte)
		require.True(t, ok)
		assert.NotNil(t, b, "driver value must be non-nil []byte for encrypted empty plaintext")
	})

	t.Run("valid_non_empty", func(t *testing.T) {
		n := NewNullEncryptedBytes("Hello World")
		v, err := n.Value()
		require.NoError(t, err)
		b, ok := v.([]byte)
		require.True(t, ok)
		assert.Equal(t, "SGVsbG8gV29ybGQ=", string(b))
	})
}

func TestNullEncryptedBytes_JSON(t *testing.T) {
	testInitCrypter(t)

	t.Run("marshal_invalid", func(t *testing.T) {
		n := NullEncryptedBytesNull()
		b, err := json.Marshal(n)
		require.NoError(t, err)
		assert.Equal(t, "null", string(b))
	})

	t.Run("marshal_valid_empty_not_null", func(t *testing.T) {
		n := NewNullEncryptedBytes("")
		b, err := json.Marshal(n)
		require.NoError(t, err)
		assert.NotEqual(t, "null", string(b))
		var raw []byte
		require.NoError(t, json.Unmarshal(b, &raw))
		require.NotNil(t, raw)
	})

	t.Run("unmarshal_null", func(t *testing.T) {
		var n NullEncryptedBytes
		require.NoError(t, json.Unmarshal([]byte("null"), &n))
		assert.False(t, n.Valid)
	})

	t.Run("round_trip", func(t *testing.T) {
		n := NewNullEncryptedBytes("Hello World")
		b, err := json.Marshal(n)
		require.NoError(t, err)
		var out NullEncryptedBytes
		require.NoError(t, json.Unmarshal(b, &out))
		assert.True(t, out.Valid)
		assert.Equal(t, "Hello World", out.Plaintext())
	})
}

func TestNullEncryptedBytes_String(t *testing.T) {
	testInitCrypter(t)

	n := NewNullEncryptedBytes("secret")
	out := fmt.Sprint(n)
	assert.NotContains(t, out, "secret")
	assert.Equal(t, "[REDACTED]", out)
}

func TestNullEncryptedBytes_GormDataType(t *testing.T) {
	var n NullEncryptedBytes
	assert.Equal(t, "nullencryptedbytes", n.GormDataType())
}

func TestNullEncryptedBytes_GormDBDataType_sqlite(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	var n NullEncryptedBytes
	assert.Equal(t, "blob", n.GormDBDataType(db, nil))
}

func TestNullEncryptedBytes_ScanBytes_BytesValue(t *testing.T) {
	testInitCrypter(t)

	t.Run("scan_nil", func(t *testing.T) {
		var n NullEncryptedBytes
		require.NoError(t, n.ScanBytes(nil))
		assert.False(t, n.Valid)
	})

	t.Run("scan_round_trip", func(t *testing.T) {
		src := NewNullEncryptedBytes("Hello World")
		ct, err := src.BytesValue()
		require.NoError(t, err)
		var dst NullEncryptedBytes
		require.NoError(t, dst.ScanBytes(ct))
		assert.True(t, dst.Valid)
		assert.Equal(t, "Hello World", dst.Plaintext())
	})

	t.Run("bytes_value_invalid", func(t *testing.T) {
		n := NullEncryptedBytesNull()
		b, err := n.BytesValue()
		require.NoError(t, err)
		assert.Nil(t, b)
	})
}

func TestNullEncryptedBytes_pgtypeMapRoundTrip(t *testing.T) {
	testInitCrypter(t)

	m := pgtype.NewMap()
	const format = pgtype.BinaryFormatCode

	in := NewNullEncryptedBytes("Hello World")
	buf, err := m.Encode(pgtype.ByteaOID, format, in, nil)
	require.NoError(t, err)

	var out NullEncryptedBytes
	require.NoError(t, m.Scan(pgtype.ByteaOID, format, buf, &out))
	assert.True(t, out.Valid)
	assert.Equal(t, "Hello World", out.Plaintext())

	var nullOut NullEncryptedBytes
	require.NoError(t, m.Scan(pgtype.ByteaOID, format, nil, &nullOut))
	assert.False(t, nullOut.Valid)
}
