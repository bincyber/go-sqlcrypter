// FIPS 140-3 mode is incompatible with GOEXPERIMENT=boringcrypto: the runtime
// panics at init when GODEBUG=fips140=only is set in a BoringCrypto binary.

//go:build !goexperiment.boringcrypto

package aesgcm

import (
	"crypto/fips140"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bincyber/go-sqlcrypter"
)

const fips140OnlyChildEnv = "SQLCRYPTER_AESGCM_FIPS140_ONLY_CHILD"

// Test_AESCrypter_FIPS140Only runs Test_AESCrypter_FIPS140OnlyChild in a new
// process with GODEBUG=fips140=only, which turns any non-approved algorithm into
// an error or a panic. The mode is fixed at process start, so it cannot be set
// in-process.
func Test_AESCrypter_FIPS140Only(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^Test_AESCrypter_FIPS140OnlyChild$", "-test.v", "-test.count=1") //nolint:gosec // re-runs this test binary
	cmd.Env = append(os.Environ(), "GODEBUG=fips140=only", fips140OnlyChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "child process output:\n%s", out)
	require.Contains(t, string(out), "--- PASS: Test_AESCrypter_FIPS140OnlyChild")
}

// Test_AESCrypter_FIPS140OnlyChild covers construction, a round trip and
// decryption of data written by earlier versions while the Go Cryptographic
// Module enforces approved-only operation.
func Test_AESCrypter_FIPS140OnlyChild(t *testing.T) {
	if os.Getenv(fips140OnlyChildEnv) == "" {
		t.Skip("runs only as a child process of Test_AESCrypter_FIPS140Only")
	}
	require.True(t, fips140.Enforced(), "GODEBUG=fips140=only is not in effect")

	key, _ := sqlcrypter.GenerateBytes(32)
	previousKey, _ := sqlcrypter.GenerateBytes(32)

	c, err := New(key, previousKey)
	require.NoError(t, err)

	plaintext := []byte("Hello World")

	got, err := decrypt(c, encrypt(t, c, plaintext))
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)

	got, err = decrypt(c, legacySeal(t, key, plaintext))
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)

	got, err = decrypt(c, legacySeal(t, previousKey, plaintext))
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}
