# HashiCorp Vault

HashiCorp Vault using the [Transit Secrets Engine](https://www.vaultproject.io/docs/secrets/transit) for encryption as a service.

### Quick Start

Sample Terraform code is available in [testing/terraform/vault](https://github.com/bincyber/go-sqlcrypter/blob/master/testing/terraform/vault) to try this provider.

### Example

```go
package main

import (
	vaultapi "github.com/hashicorp/vault/api"

	"github.com/bincyber/go-sqlcrypter"
	"github.com/bincyber/go-sqlcrypter/providers/vault"
)

func main() {
	// Token will be read from VAULT_TOKEN envvar
	client, err := vaultapi.NewClient(&vaultapi.Config{
		Address: "http://localhost:8200",
	})
	if err != nil {
		// handle error
	}

	vaultCrypter, err := vault.New(client, "transit", "go-sqlcrypter")
	if err != nil {
		// handle err
	}

	sqlcrypter.Init(vaultCrypter)
}
```

### Encryption as a Service

Encryption and decryption of sensitive data is entirely delegated to Vault. The [Encrypt](https://www.vaultproject.io/api-docs/secret/transit#encrypt-data) and [Decrypt](https://www.vaultproject.io/api-docs/secret/transit#decrypt-data) endpoints of the Transit secrets engine are used. The data encryption key (DEK) is never accessed by the application. Vault also does not store the data sent to the Transit secrets engine.

### Convergent Encryption

[Convergent Encryption](https://www.vaultproject.io/docs/secrets/transit#convergent-encryption) is not supported at this time.
