package dsa_test

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/crypto/dsa"
	"github.com/tbd54566975/web5-go/crypto/dsa/ecdsa"
	"github.com/tbd54566975/web5-go/crypto/dsa/eddsa"
)

func TestGeneratePrivateKeySECP256K1(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmID.SECP256K1)

	assert.NoError(t, err)
	assert.Equal[string](t, privateJwk.CRV, ecdsa.SECP256K1JWACurve)
	assert.Equal[string](t, privateJwk.KTY, ecdsa.KeyType)
	assert.True(t, privateJwk.D != "", "privateJwk.D is empty")
	assert.True(t, privateJwk.X != "", "privateJwk.X is empty")
	assert.True(t, privateJwk.Y != "", "privateJwk.Y is empty")
}

func TestGeneratePrivateKeyED25519(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmID.ED25519)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err.Error())
	}

	assert.NoError(t, err)
	assert.Equal[string](t, privateJwk.CRV, eddsa.ED25519JWACurve)
	assert.Equal[string](t, privateJwk.KTY, eddsa.KeyType)
	assert.True(t, privateJwk.D != "", "privateJwk.D is empty")
	assert.True(t, privateJwk.X != "", "privateJwk.X is empty")
}

func TestSignSECP256K1(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmID.SECP256K1)
	assert.NoError(t, err)

	payload := []byte("hello world")
	signature, err := dsa.Sign(payload, privateJwk)

	assert.NoError(t, err)
	assert.True(t, len(signature) == 64, "invalid signature length")
}

func TestSignED25519(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmID.ED25519)
	assert.NoError(t, err)

	payload := []byte("hello world")
	signature, err := dsa.Sign(payload, privateJwk)

	assert.NoError(t, err)
	assert.True(t, len(signature) == 64, "invalid signature length")
}

func TestSignDeterministicSECP256K1(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmID.SECP256K1)
	assert.NoError(t, err)

	payload := []byte("hello world")
	signature1, err := dsa.Sign(payload, privateJwk)
	assert.NoError(t, err, "failed to sign")

	signature2, err := dsa.Sign(payload, privateJwk)
	assert.NoError(t, err)

	assert.Equal(t, signature1, signature2, "signature is not deterministic")
}

func TestSignDeterministicED25519(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmID.ED25519)
	assert.NoError(t, err)

	payload := []byte("hello world")
	signature1, err := dsa.Sign(payload, privateJwk)
	assert.NoError(t, err, "failed to sign")

	signature2, err := dsa.Sign(payload, privateJwk)
	assert.NoError(t, err)

	assert.Equal(t, signature1, signature2, "signature is not deterministic")
}

func TestVerifySECP256K1(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmID.SECP256K1)
	assert.NoError(t, err)

	payload := []byte("hello world")
	signature, err := dsa.Sign(payload, privateJwk)
	assert.NoError(t, err)

	publicJwk := dsa.GetPublicKey(privateJwk)

	legit, err := dsa.Verify(payload, signature, publicJwk)
	assert.NoError(t, err)

	assert.True(t, legit, "failed to verify signature")
}

func TestVerifyED25519(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmID.ED25519)
	assert.NoError(t, err)

	payload := []byte("hello world")
	signature, err := dsa.Sign(payload, privateJwk)

	assert.NoError(t, err)

	publicJwk := dsa.GetPublicKey(privateJwk)

	legit, err := dsa.Verify(payload, signature, publicJwk)
	assert.NoError(t, err)

	assert.True(t, legit, "failed to verify signature")
}
