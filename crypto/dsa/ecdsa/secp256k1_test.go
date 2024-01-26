package ecdsa_test

import (
	"testing"

	"github.com/tbd54566975/web5-go/crypto/dsa/ecdsa"
)

func TestSECP256K1GeneratePrivateKey(t *testing.T) {
	key, err := ecdsa.SECP256K1GeneratePrivateKey()
	if err != nil {
		t.Errorf("failed to generate private key: %v", err.Error())
	}

	if key.KTY != ecdsa.KeyType {
		t.Errorf("unexpected key type. expected: %v got: %v", ecdsa.KeyType, key.KTY)
	}

	if key.CRV != ecdsa.SECP256K1JWACurve {
		t.Errorf("unexpected curve. expected: %v got: %v", ecdsa.SECP256K1JWACurve, key.CRV)
	}

	if key.D == "" {
		t.Errorf("d is empty")
	}

	if key.X == "" {
		t.Errorf("x is empty")
	}

	if key.Y == "" {
		t.Errorf("y is empty")
	}
}
