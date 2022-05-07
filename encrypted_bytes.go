package sqlcrypter

import (
	"bytes"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

var (
	_ driver.Valuer    = &EncryptedBytes{}
	_ sql.Scanner      = &EncryptedBytes{}
	_ json.Marshaler   = &EncryptedBytes{}
	_ json.Unmarshaler = &EncryptedBytes{}
)

func NewEncryptedBytes(s string) EncryptedBytes {
	e := &EncryptedBytes{}

	if s == "" {
		return []byte(nil)
	}

	*e = []byte(s)
	return *e
}

type EncryptedBytes []byte

func (e *EncryptedBytes) GormDataType() string {
	return "encryptedbytes"
}

func (e *EncryptedBytes) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	switch db.Dialector.Name() {
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

func (e EncryptedBytes) String() string {
	return string(e)
}

func (e EncryptedBytes) Bytes() []byte {
	return e[:]
}

// Scan implements the scanner interface
func (e *EncryptedBytes) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to read value as bytes")
	}

	// Dont attempt to decrypt if value is nil
	if b == nil {
		return nil
	}

	// Decrypt value to e
	reader := bytes.NewReader(b)
	writer := new(bytes.Buffer)

	if err := Decrypt(writer, reader); err != nil {
		return err
	}

	*e = writer.Bytes()

	return nil
}

// Value implements the valuer interface
func (e EncryptedBytes) Value() (driver.Value, error) {
	// nil will be stored as null in the database
	if len(e) == 0 {
		var b []byte
		return b, nil
	}

	// Encrypt contents of e before storing in the database
	reader := bytes.NewReader(e)
	writer := new(bytes.Buffer)

	if err := Encrypt(writer, reader); err != nil {
		return nil, err
	}

	return writer.Bytes(), nil
}

// MarshalJSON implements json.Marshaler interface
func (e EncryptedBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.String())
}

// UnmarshalJSON implements json.Unmarshaler interface
func (e *EncryptedBytes) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	*e = []byte(s)
	return nil
}
