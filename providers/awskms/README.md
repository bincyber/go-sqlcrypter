# AWS KMS

AWS KMS using [envelope encryption](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#enveloping) with 256-bit AES in Galois/Counter Mode (GCM).

### Quick Start

Sample Terraform code is available in [testing/terraform/awskms](https://github.com/bincyber/go-sqlcrypter/blob/master/testing/terraform/awskms) to try this provider with AWS KMS.

### Example

```go
package main

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/dgraph-io/ristretto"

	"github.com/bincyber/go-sqlcrypter"
	"github.com/bincyber/go-sqlcrypter/providers/awskms"
)

func main() {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		// handle error
	}

	client := kms.NewFromConfig(cfg)

	kmsCrypter, err := awskms.New(
		context.Background(),
		client,
		"alias/sqlcrypter",
		// Optioanlly configure request timeout, rate limits, and cache
		awskms.WithRequestTimeout(2*time.Second),
		awskms.WithKMSDecryptRateLimit(5, 10)
		awskms.WithDEKCacheConfig(ristretto.Config{
			MaxCost:     int64(100_000),
			NumCounters: int64(500_000),
			BufferItems: int64(64),
		}),
	)
	if err != nil {
		//handle error
	}

	sqlcrypter.Init(kmsCrypter)
}
```

### Envelope Encryption

`KMSCrypter` uses envelope encryption. When `awskms.New()` is called, a request is made to the the KMS [GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html) API to retrieve a 256-bit symmetric data encryption key (DEK). This DEK is used to encrypt data using AES GCM instead of calling the KMS [Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) and [Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) APIs every time. The encrypted DEK is stored alongside the ciphertext. To decrypt previous DEKs stored alongside ciphertext, a request is made to the KMS [Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html) API. The decrypted DEK is then cached in memory to avoid repetitive API calls to KMS.

### Request Deadlines

Each call to KMS (`GenerateDataKey` during `New`, and `Decrypt` when decrypting an unknown encrypted DEK) runs under a **deadline**. The default is **2 seconds**. This can be overridden with `WithRequestTimeout()` option.

### Cache

Previous DEKs decrypted via KMS are cached in a [Ristretto](https://github.com/dgraph-io/ristretto) in-memory cache.

Defaults:
- `MaxCost` 1,000,000 (1MB)
- `NumCounters` 50,000
- `BufferItems` 64.

This can be overridden with `WithDEKCacheConfig(ristretto.Config{...})`.

### Mitigating Denial of Wallet

If an attacker can invoke `Decrypt` with arbitrary ciphertext, they can force **cache misses** by supplying **unique** encrypted DEK blobs. Each miss triggers a billable **KMS Decrypt** until the in-memory cache fills or entries expire.

Mitigations in this provider:

- **In-memory cache** of decrypted DEKs (TTL 60 minutes) so repeated blobs do not re-hit KMS.
- **Optional rate limit** on the KMS `Decrypt` path only: `WithKMSDecryptRateLimit(rps, burst)` using a token bucket. When the limit is exceeded, `Decrypt` returns `awskms.ErrKMSDecryptRateLimited` **before** calling AWS (map to HTTP 429 or similar at the application layer).

You should still enforce **authentication**, **least-privilege IAM** on the CMK, **AWS Budgets** / billing alarms, and **CloudWatch** throttling alarms for KMS. Edge rate limiting (API gateway, WAF) is recommended for internet-facing services.

### Testing

[nsmith/local-kms](https://github.com/nsmithuk/local-kms) is used to help with testing. The seed file used is located in [testing/seed.yaml](https://github.com/bincyber/go-sqlcrypter/blob/master/providers/awskms/docs.md).
