package crypto_test

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/crypto"
)

func Test_GenerateEntropy(t *testing.T) {
	size := 16
	bytes, err := crypto.GenerateEntropy(size)
	assert.NoError(t, err)
	assert.Equal(t, size, len(bytes))
}

func Test_GenerateEntropy_InvalidSize(t *testing.T) {
	bytes, err := crypto.GenerateEntropy(0)
	assert.Error(t, err)
	assert.Equal(t, nil, bytes)

	bytes, err = crypto.GenerateEntropy(-1)
	assert.Error(t, err)
	assert.Equal(t, nil, bytes)
}

func Test_GenerateNonce(t *testing.T) {
	nonceMap := make(map[string]bool)

	for i := 0; i < 1000000; i++ {
		nonce, err := crypto.GenerateNonce()
		assert.NoError(t, err)
		assert.Equal(t, 32, len(nonce))

		nonceMap[nonce] = true
	}

	// Assert that we have 1000000 unique nonces
	assert.Equal(t, 1000000, len(nonceMap))
}
