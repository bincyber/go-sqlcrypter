package sqlcrypter

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// NullEncryptedBytes is a nullable encrypted column value for database/sql,
// GORM, JSON, and pgx/sqlc (BYTEA) workflows.
//
// Semantics:
//   - Valid == false: SQL NULL; JSON null; Plaintext/Bytes are empty/nil.
//   - Valid == true: plaintext is stored encrypted, including empty plaintext
//     (distinct from SQL NULL).
type NullEncryptedBytes struct {
	Data  EncryptedBytes
	Valid bool
}

// NewNullEncryptedBytes returns a present value with plaintext s (empty string allowed).
func NewNullEncryptedBytes(s string) NullEncryptedBytes {
	var data EncryptedBytes
	if s == "" {
		data = EncryptedBytes([]byte{})
	} else {
		data = EncryptedBytes([]byte(s))
	}
	return NullEncryptedBytes{Data: data, Valid: true}
}

// NullEncryptedBytesNull returns an absent (SQL NULL) value.
func NullEncryptedBytesNull() NullEncryptedBytes {
	return NullEncryptedBytes{Valid: false}
}

func (n *NullEncryptedBytes) GormDataType() string {
	return "nullencryptedbytes"
}

func (n *NullEncryptedBytes) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	switch db.Name() {
	case "mysql":
		return "binary"
	case "postgres":
		return "bytea"
	case "sqlite":
		return "blob"
	case "sqlserver":
		return "varbinary"
	default:
		return ""
	}
}

// String intentionally returns a redacted placeholder.
func (n NullEncryptedBytes) String() string {
	return "[REDACTED]"
}

// Plaintext returns decrypted plaintext when Valid; otherwise "".
func (n NullEncryptedBytes) Plaintext() string {
	if !n.Valid {
		return ""
	}
	return string(n.Data)
}

// Bytes returns a slice view of plaintext when Valid; otherwise nil.
// The returned slice aliases Data; mutating it mutates the stored plaintext.
func (n NullEncryptedBytes) Bytes() []byte {
	if !n.Valid {
		return nil
	}
	return n.Data[:]
}

// Scan implements sql.Scanner.
func (n *NullEncryptedBytes) Scan(value any) error {
	if value == nil {
		n.Valid = false
		n.Data = nil
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("sqlcrypter: NullEncryptedBytes.Scan expected []byte, got %T", value)
	}
	if b == nil {
		n.Valid = false
		n.Data = nil
		return nil
	}
	pt, err := decryptCiphertextBytes(b)
	if err != nil {
		return err
	}
	n.Data = pt
	n.Valid = true
	return nil
}

// Value implements driver.Valuer.
func (n NullEncryptedBytes) Value() (driver.Value, error) {
	if !n.Valid {
		//nolint:nilnil // driver.Valuer: nil value with nil error means SQL NULL
		return nil, nil
	}
	return encryptPlaintextBytes(n.Data)
}

// MarshalJSON encodes absent values as JSON null; present values as base64 ciphertext.
func (n NullEncryptedBytes) MarshalJSON() ([]byte, error) {
	if !n.Valid {
		return []byte("null"), nil
	}
	ciphertext, err := encryptPlaintextBytes(n.Data)
	if err != nil {
		return nil, err
	}
	return json.Marshal(ciphertext)
}

// UnmarshalJSON decodes JSON null as absent; otherwise expects base64 ciphertext bytes.
func (n *NullEncryptedBytes) UnmarshalJSON(data []byte) error {
	var ciphertext []byte
	if err := json.Unmarshal(data, &ciphertext); err != nil {
		return err
	}
	if ciphertext == nil {
		n.Valid = false
		n.Data = nil
		return nil
	}
	n.Valid = true
	return n.Scan(ciphertext)
}

// ScanBytes implements pgtype.BytesScanner for pgx/sqlc BYTEA columns.
func (n *NullEncryptedBytes) ScanBytes(src []byte) error {
	if src == nil {
		n.Valid = false
		n.Data = nil
		return nil
	}
	// src is only valid until the next database call; copy before Scan.
	b := append([]byte(nil), src...)
	return n.Scan(b)
}

// BytesValue implements pgtype.BytesValuer for pgx/sqlc BYTEA columns.
func (n NullEncryptedBytes) BytesValue() ([]byte, error) {
	v, err := n.Value()
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, nil
	}
	b, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("sqlcrypter: NullEncryptedBytes.BytesValue expected []byte, got %T", v)
	}
	return b, nil
}

var (
	_ driver.Valuer       = &NullEncryptedBytes{}
	_ sql.Scanner         = &NullEncryptedBytes{}
	_ json.Marshaler      = &NullEncryptedBytes{}
	_ json.Unmarshaler    = &NullEncryptedBytes{}
	_ fmt.Stringer        = &NullEncryptedBytes{}
	_ pgtype.BytesScanner = &NullEncryptedBytes{}
	_ pgtype.BytesValuer  = &NullEncryptedBytes{}
)
