# AWS KMS

AWS KMS using [envelope encryption](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#enveloping) with 256-bit AES in Galois/Counter Mode (GCM).

### Quick Start

Sample Terraform code is available in [testing/terraform/awskms](https://github.com/bincyber/go-sqlcrypter/blob/master/testing/terraform/awskms) to try this provider with AWS KMS.

### Example

```go
package main

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/bincyber/go-sqlcrypter"
	"github.com/bincyber/go-sqlcrypter/providers/awskms"
)

func main() {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		// handle error
	}

	client := kms.NewFromConfig(cfg)

	kmsCrypter, err := awskms.New(context.Background(), client, "alias/sqlcrypter")
	if err != nil {
		//handle error
	}

	sqlcrypter.Init(kmsCrypter)
}
```

### Envelope Encryption

`KMSCrypter` uses envelope encryption. When `awskms.New()` is called, a request is made to the the KMS [GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html) API to retrieve a 256-bit symmetric data encryption key (DEK). This DEK is used to encrypt data using AES GCM instead of calling the KMS [Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) and [Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) APIs every time. The encrypted DEK is stored alongside the ciphertext. To decrypt previous DEKs stored alongside ciphertext, a request is made to the KMS [Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) API. The decrypted DEK is then cached in memory to avoid repetitive API calls to KMS.

### Testing

[nsmith/local-kms](https://github.com/nsmithuk/local-kms) is used to help with testing. The seed file used is located in [testing/seed.yaml](https://github.com/bincyber/go-sqlcrypter/blob/master/providers/awskms/docs.md).
