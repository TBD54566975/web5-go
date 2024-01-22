package crypto_test

import (
	"testing"

	"github.com/tbd54566975/web5-go/crypto"
	"github.com/tbd54566975/web5-go/crypto/dsa"
)

func TestGeneratePrivateKey(t *testing.T) {
	keyManager := crypto.NewInMemoryKeyManager()

	keyID, err := keyManager.GeneratePrivateKey(dsa.AlgorithmID.SECP256K1)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err.Error())
	}

	if keyID == "" {
		t.Errorf("keyID is empty")
	}
}

func TestGetPublicKey(t *testing.T) {
	keyManager := crypto.NewInMemoryKeyManager()

	keyID, err := keyManager.GeneratePrivateKey(dsa.AlgorithmID.SECP256K1)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err.Error())
	}

	publicKey, err := keyManager.GetPublicKey(keyID)
	if err != nil {
		t.Errorf("failed to get public key: %v", err.Error())
	}

	thumbprint, err := publicKey.ComputeThumbprint()
	if err != nil {
		t.Errorf("failed to compute thumbprint: %v", err.Error())
	}

	if thumbprint != keyID {
		t.Errorf("unexpected keyID. expected: %v got: %v", keyID, thumbprint)
	}
}

func TestSign(t *testing.T) {
	keyManager := crypto.NewInMemoryKeyManager()

	keyID, err := keyManager.GeneratePrivateKey(dsa.AlgorithmID.SECP256K1)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err.Error())
	}

	payload := []byte("hello world")
	signature, err := keyManager.Sign(keyID, payload)
	if err != nil {
		t.Errorf("failed to sign payload: %v", err.Error())
	}

	if signature == nil {
		t.Errorf("signature is nil")
	}
}
