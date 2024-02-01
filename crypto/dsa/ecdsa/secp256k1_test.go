package ecdsa_test

import (
	"encoding/hex"
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

func TestSECP256K1BytesToPublicKey_Bad(t *testing.T) {
	_, err := ecdsa.SECP256K1BytesToPublicKey([]byte{0x00, 0x01, 0x02, 0x03})
	assert.Error(t, err)
}

func TestSECP256K1BytesToPublicKey_Uncompressed(t *testing.T) {
	// vector taken from https://github.com/TBD54566975/web5-js/blob/dids-new-crypto/packages/crypto/tests/fixtures/test-vectors/secp256k1/bytes-to-public-key.json
	publicKeyHex := "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
	pubKeyBytes, err := hex.DecodeString(publicKeyHex)
	assert.NoError(t, err)

	jwk, err := ecdsa.SECP256K1BytesToPublicKey(pubKeyBytes)
	assert.NoError(t, err)

	assert.Equal(t, jwk.CRV, ecdsa.SECP256K1JWACurve)
	assert.Equal(t, jwk.KTY, ecdsa.KeyType)
	assert.Equal(t, jwk.X, "eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g")
	assert.Equal(t, jwk.Y, "SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg")
}
