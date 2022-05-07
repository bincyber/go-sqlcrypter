# AES GCM

256-bit AES in Galois/Counter Mode (GCM)

### Example

```go
package main

import (
	"github.com/bincyber/go-sqlcrypter"
	"github.com/bincyber/go-sqlcrypter/aesgcm"
)

func main() {
	s := "32-byte-hex-encoded-data-encryption-key-here"

	key, err := hex.DecodeString(s)
	if err != nil {
		// handle error
	}

	aesCrypter, err := aesgcm.New(key, nil)
	if err != nil {
		// handle error
	}
	sqlcrypter.Init(aesCrypter)
}
```

### Key Rotation

`AESCrypter` supports [key rotation](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#key-lifetimes-and-rotation) by allowing two data encryption keys (DEKs) to be specified during initialization. When `aesgcm.New()` is called with two DEKs, the first key is used to encrypt (and decrypt) any new data, while the second key is only used to decrypt existing data.

**Note**: Before the old key can stop being used, any existing data must be re-encrypted with the new key by running Update queries over the database records. Handling this is out of scope for this library.
