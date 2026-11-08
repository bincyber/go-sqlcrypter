# AES-GCM

256-bit AES in Galois/Counter Mode (GCM)

### Example

```go
package main

import (
	"encoding/hex"

	"github.com/bincyber/go-sqlcrypter"
	"github.com/bincyber/go-sqlcrypter/providers/aesgcm"
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

### Operational Limits

> [!WARNING]
> **Do not encrypt more than 2^32 values with any single DEK.** Plan [key rotation](#key-rotation) and re-encryption well before reaching that bound.

The AES-GCM provider uses a randomly generated 12-byte nonce (IV) for each encryption operation. Since v0.4.0 the nonce is generated inside `crypto/cipher` by [`cipher.NewGCMWithRandomNonce`](https://pkg.go.dev/crypto/cipher#NewGCMWithRandomNonce), which is the form the Go Cryptographic Module accepts when it enforces approved-only operation (`GODEBUG=fips140=only`). Earlier versions generated the nonce in this provider. This library does not enforce a maximum number of encryptions per DEK at runtime; Go documents the same 2^32 bound for `NewGCMWithRandomNonce`.

Per [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) section 8.3, implementations using randomly generated IVs should limit the number of encryptions performed under a single key to reduce the probability of nonce collisions. In large-scale database column encryption deployments, where many rows may share the same DEK, this limit can become relevant over time. Since ciphertexts are typically stored together, an attacker who can access them may benefit from any nonce collisions that occur. Nonce reuse under the same key can undermine GCM confidentiality and integrity, potentially enabling plaintext recovery or ciphertext forgery.

The mitigation for this issue is operational: rotate DEKs as needed and re-encrypt data.

### Ciphertext Format

Every value is stored as `nonce (12 bytes) || ciphertext || authentication tag (16 bytes)`, with no additional authenticated data. The layout has not changed between versions: data encrypted by any version of this provider decrypts with any other version, and data encrypted by v0.4.0 or later decrypts with earlier versions on a toolchain where they can start (earlier versions cannot start under `GODEBUG=fips140=only`). No re-encryption is needed when upgrading.

On toolchains whose AES block cipher is not the standard library's (for example `GOEXPERIMENT=boringcrypto`), `cipher.NewGCMWithRandomNonce` is unavailable and the provider falls back to `cipher.NewGCM` with a nonce it generates itself. The stored layout is the same.

### Key Rotation

`AESCrypter` supports [key rotation](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#key-lifetimes-and-rotation) by allowing two data encryption keys (DEKs) to be specified during initialization. When `aesgcm.New()` is called with two DEKs, the first key is used to encrypt (and decrypt) any new data, while the second key is only used to decrypt existing data.

**Note**: Before the old key can stop being used, any existing data must be re-encrypted with the new key by running Update queries over the database records. Handling this is out of scope for this library.
