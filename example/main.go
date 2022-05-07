package main

import (
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/hashicorp/go-hclog"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/bincyber/go-sqlcrypter"
	"github.com/bincyber/go-sqlcrypter/providers/aesgcm"
)

type Employee struct {
	gorm.Model
	FirstName  string
	LastName   string
	SSN        sqlcrypter.EncryptedBytes
	Email      string `gorm:"unique"`
	Title      string
	Department string
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:           hclog.LevelFromString("DEBUG"),
		Output:          os.Stderr,
		IncludeLocation: true,
		JSONFormat:      false,
		Color:           hclog.AutoColor,
	})

	// Initialize sqlcrypter with AES GCM provider
	key, err := hex.DecodeString("fb7f69d3f824045c2685ad859593470df11e45256480802517cb20fc19b0d15e")
	if err != nil {
		logger.Error("failed to hex decode data encryption key")
		os.Exit(1)
	}

	aesCrypter, err := aesgcm.New(key, nil)
	if err != nil {
		logger.Error("failed to create AES GCM crypter")
	}

	sqlcrypter.Init(aesCrypter)

	// Connect to the sqlite database
	db, err := gorm.Open(sqlite.Open("example.db"), &gorm.Config{})
	if err != nil {
		logger.Error("failed to connect to sqlite database", "error", err)
		os.Exit(1)
	}

	// Migrate the schema
	db.AutoMigrate(&Employee{})

	// Create new employee
	newEmployee := &Employee{
		FirstName:  "Doug",
		LastName:   "Rattman",
		SSN:        sqlcrypter.NewEncryptedBytes("999-00-1337"),
		Email:      "rattman@aperturescience.com",
		Title:      "Scientist",
		Department: "Enrichment Center",
	}

	if err := db.Create(newEmployee).Error; err != nil {
		logger.Error("failed to create new employee record", "error", err)
		os.Exit(1)
	}

	// Query and write result as JSON to stdout
	var employee *Employee

	result := db.First(&employee, "title = ?", "Scientist")
	if result.Error != nil {
		logger.Error("failed to query employee records", "error", err)
		os.Exit(1)
	}

	if err := json.NewEncoder(os.Stdout).Encode(employee); err != nil {
		logger.Error("failed to encode to json", "error", err)
		os.Exit(1)
	}

	// Update SSN
	employee.SSN = sqlcrypter.NewEncryptedBytes("999-00-1347")
	db.Save(&employee)

	if err := json.NewEncoder(os.Stdout).Encode(employee); err != nil {
		logger.Error("failed to encode to json", "error", err)
		os.Exit(1)
	}
}
