package dsa_test

import (
	"testing"

	"github.com/tbd54566975/web5-go/crypto/dsa"
	"github.com/tbd54566975/web5-go/crypto/dsa/ecdsa"
	"github.com/tbd54566975/web5-go/crypto/dsa/eddsa"
)

func TestGeneratePrivateKeySECP256K1(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmID.SECP256K1)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err.Error())
	}

	if privateJwk.CRV != ecdsa.SECP256K1JWACurve {
		t.Errorf("unexpected CRV. expected: %v got: %v", ecdsa.SECP256K1JWACurve, privateJwk.CRV)
	}

	if privateJwk.KTY != ecdsa.KeyType {
		t.Errorf("unexpected KTY. expected: %v got: %v", ecdsa.KeyType, privateJwk.KTY)
	}

	if privateJwk.D == "" {
		t.Errorf("privateJwk.D is empty")
	}

	if privateJwk.X == "" || privateJwk.Y == "" {
		t.Errorf("privateJwk.X or privateJwk.Y is empty")
	}
}

func TestGeneratePrivateKeyED25519(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmID.ED25519)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err.Error())
	}

	if privateJwk.CRV != eddsa.ED25519JWACurve {
		t.Errorf("unexpected CRV. expected: %v got: %v", eddsa.ED25519JWACurve, privateJwk.CRV)
	}

	if privateJwk.KTY != "OKP" {
		t.Errorf("unexpected KTY. expected: %v got: %v", "OKP", privateJwk.KTY)
	}

	if privateJwk.D == "" {
		t.Errorf("privateJwk.D is empty")
	}

	if privateJwk.X == "" {
		t.Errorf("privateJwk.X is empty")
	}
}

func TestSignSECP256K1(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmID.SECP256K1)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err.Error())
	}

	payload := []byte("hello world")
	signature, err := dsa.Sign(payload, privateJwk)
	if err != nil {
		t.Errorf("failed to sign: %v", err.Error())
	}

	if len(signature) != 64 {
		t.Errorf("invalid signature length. expected 64, got %d", len(signature))
	}
}

func TestSignED25519(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmID.ED25519)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err.Error())
	}

	payload := []byte("hello world")
	signature, err := dsa.Sign(payload, privateJwk)
	if err != nil {
		t.Errorf("failed to sign: %v", err.Error())
	}

	if len(signature) != 64 {
		t.Errorf("invalid signature length. expected 64, got %d", len(signature))
	}
}

func TestSignDeterministicSECP256K1(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmID.SECP256K1)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err.Error())
	}

	payload := []byte("hello world")
	signature1, err := dsa.Sign(payload, privateJwk)
	if err != nil {
		t.Errorf("failed to sign: %v", err.Error())
	}

	signature2, err := dsa.Sign(payload, privateJwk)
	if err != nil {
		t.Errorf("failed to sign: %v", err.Error())
	}

	if string(signature1) != string(signature2) {
		t.Errorf("signature is not deterministic")
	}
}

func TestSignDeterministicED25519(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmID.ED25519)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err.Error())
	}

	payload := []byte("hello world")
	signature1, err := dsa.Sign(payload, privateJwk)
	if err != nil {
		t.Errorf("failed to sign: %v", err.Error())
	}

	signature2, err := dsa.Sign(payload, privateJwk)
	if err != nil {
		t.Errorf("failed to sign: %v", err.Error())
	}

	if string(signature1) != string(signature2) {
		t.Errorf("signature is not deterministic")
	}
}

func TestVerifySECP256K1(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmID.SECP256K1)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err.Error())
	}

	payload := []byte("hello world")
	signature, err := dsa.Sign(payload, privateJwk)
	if err != nil {
		t.Errorf("failed to sign: %v", err.Error())
	}

	publicJwk := dsa.GetPublicKey(privateJwk)

	legit, err := dsa.Verify(payload, signature, publicJwk)
	if err != nil {
		t.Errorf("failed to verify: %v", err.Error())
	}

	if !legit {
		t.Errorf("failed to verify signature")
	}
}

func TestVerifyED25519(t *testing.T) {
	privateJwk, err := dsa.GeneratePrivateKey(dsa.AlgorithmID.ED25519)
	if err != nil {
		t.Errorf("failed to generate private key: %v", err.Error())
	}

	payload := []byte("hello world")
	signature, err := dsa.Sign(payload, privateJwk)
	if err != nil {
		t.Errorf("failed to sign: %v", err.Error())
	}

	publicJwk := dsa.GetPublicKey(privateJwk)

	legit, err := dsa.Verify(payload, signature, publicJwk)
	if err != nil {
		t.Errorf("failed to verify: %v", err.Error())
	}

	if !legit {
		t.Errorf("failed to verify signature")
	}
}
