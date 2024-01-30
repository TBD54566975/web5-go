package ecdsa_test

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/crypto/dsa/ecdsa"
)

func TestSECP256K1GeneratePrivateKey(t *testing.T) {
	key, err := ecdsa.SECP256K1GeneratePrivateKey()
	assert.NoError(t, err)

	assert.Equal(t, ecdsa.KeyType, key.KTY)
	assert.Equal(t, ecdsa.SECP256K1JWACurve, key.CRV)
	assert.True(t, key.D != "", "privateJwk.D is empty")
	assert.True(t, key.X != "", "privateJwk.X is empty")
	assert.True(t, key.Y != "", "privateJwk.Y is empty")
}
