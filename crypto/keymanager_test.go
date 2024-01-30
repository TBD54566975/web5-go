package crypto_test

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/crypto"
	"github.com/tbd54566975/web5-go/crypto/dsa"
)

func TestGeneratePrivateKey(t *testing.T) {
	keyManager := crypto.NewLocalKeyManager()

	keyID, err := keyManager.GeneratePrivateKey(dsa.AlgorithmID.SECP256K1)
	assert.NoError(t, err)

	assert.True(t, keyID != "", "keyID is empty")
}

func TestGetPublicKey(t *testing.T) {
	keyManager := crypto.NewLocalKeyManager()

	keyID, err := keyManager.GeneratePrivateKey(dsa.AlgorithmID.SECP256K1)
	assert.NoError(t, err)

	publicKey, err := keyManager.GetPublicKey(keyID)
	assert.NoError(t, err)

	thumbprint, err := publicKey.ComputeThumbprint()
	assert.NoError(t, err)

	assert.Equal[string](t, thumbprint, keyID, "unexpected keyID")
}

func TestSign(t *testing.T) {
	keyManager := crypto.NewLocalKeyManager()

	keyID, err := keyManager.GeneratePrivateKey(dsa.AlgorithmID.SECP256K1)
	assert.NoError(t, err)

	payload := []byte("hello world")
	signature, err := keyManager.Sign(keyID, payload)
	assert.NoError(t, err)

	if signature == nil {
		t.Errorf("signature is nil")
	}

	assert.True(t, signature != nil, "signature is nil")
}
