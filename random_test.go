package sqlcrypter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateBytes(t *testing.T) {
	tests := []struct {
		name    string
		n       int
		wantLen int
	}{
		{name: "n_zero", n: 0, wantLen: 0},
		{name: "n_one", n: 1, wantLen: 1},
		{name: "n_16", n: 16, wantLen: 16},
		{name: "n_256", n: 256, wantLen: 256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateBytes(tt.n)
			require.NoError(t, err)
			require.Len(t, got, tt.wantLen)
		})
	}

	t.Run("distinct_outputs", func(t *testing.T) {
		a, err := GenerateBytes(32)
		require.NoError(t, err)
		b, err := GenerateBytes(32)
		require.NoError(t, err)
		assert.NotEqual(t, a, b, "two 32-byte draws from crypto/rand should almost never match")
	})
}

func TestGenerateBytes_Panics(t *testing.T) {
	assert.Panics(t, func() {
		_, _ = GenerateBytes(-1)
	})
}
