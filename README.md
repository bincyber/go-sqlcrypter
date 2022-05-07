# go-sqlcrypter

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://mit-license.org/)
[![GoDoc](https://godoc.org/github.com/bincyber/go-sqlcrypter?status.svg)](https://godoc.org/github.com/bincyber/go-sqlcrypter)
[![Go Report Card](https://img.shields.io/badge/go%20report-A%2B-brightgreen)](https://goreportcard.com/report/github.com/bincyber/go-sqlcrypter)
[![test](https://github.com/bincyber/go-sqlcrypter/actions/workflows/test.yml/badge.svg)](https://github.com/bincyber/go-sqlcrypter/actions/workflows/test.yml)

`go-sqlcrypter` is a Go package that enables sensitive data to be encrypted at rest within a relational database. A custom type _[EncryptedBytes](https://github.com/bincyber/go-sqlcrypter/blob/master/encrypted_bytes.go#L33)_ is provided which implements the `sql.Scanner` and `driver.Valuer` interfaces allowing data to be encrypted and decrypted when writing to and reading from a SQL database. [Column-level encryption](https://en.wikipedia.org/wiki/Column_level_encryption) provides an additional layer of security.

The following encryption providers are supported:

* [AES GCM](https://github.com/bincyber/go-sqlcrypter/blob/master/providers/aesgcm/README.md)
* [AWS KMS](https://github.com/bincyber/go-sqlcrypter/blob/master/providers/awskms/README.md)
* [HashiCorp Vault](https://github.com/bincyber/go-sqlcrypter/blob/master/providers/vault/README.md)

Refer to each provider for documentation and examples.

### Install

```
go get -u github.com/bincyber/go-sqlcrypter
```

### Usage

Configure the encryption provider of your choice:

```go
key := []byte("abcdef01234567899876543210fedcba")
provider, err := aescrypter.New(key, nil)
if err != nil {
    log.Fatalf("failed to initialize AES crypter. Error: %s", err)
}
```

Initialize the sqlcrypter with the encryption provider:

```go
sqlcrypter.Init(provider)
```

Use the custom type _[EncryptedBytes](https://github.com/bincyber/go-sqlcrypter/blob/master/encrypted_bytes.go#L33)_ for any sensitive data:

```go
type Employee struct {
	Name  string
	SSN   sqlcrypter.EncryptedBytes
	Email string
	Title string
}

func main() {
	e := &Employee{
		Name:  "Tony Stark",
		SSN:   sqlcrypter.NewEncryptedBytes("999-00-1234"),
		Email: "tony@starkindustries.com",
		Title: "Genius, Billionaire, Playboy, Philanthropist",
	}
}

```

For a full example, see [example/main.go](https://github.com/bincyber/go-sqlcrypter/blob/master/example/main.go).

### Development

[docker-compose](https://docs.docker.com/compose/) is used to help with local development and testing. See [testing/docker-compose.yml](https://github.com/bincyber/go-sqlcrypter/blob/master/testing/docker-compose.yml)

To bring up the development environment:

```
make dev/up
make terraform/apply
```

To run the test suite:

```
make go/test
```

### Contributing

Contributions of new encryption providers (eg, Azure Key Vault, GCP KMS, etc.) are more than welcome!


## License

The source code for this library is licensed under the MIT license, which you can find in the `LICENSE` file.
