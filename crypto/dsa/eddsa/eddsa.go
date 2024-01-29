// Package eddsa implements the EdDSA signature schemes as per RFC 8032
// https://tools.ietf.org/html/rfc8032. Note: Currently only Ed25519 is supported
package eddsa

import (
	"errors"
	"fmt"

	"github.com/tbd54566975/web5-go/jwk"
)

const (
	JWA     string = "EdDSA"
	KeyType string = "OKP"
)

var AlgorithmIDs = map[string]bool{
	ED25519AlgorithmID: true,
}

func GeneratePrivateKey(algorithmID string) (jwk.JWK, error) {
	switch algorithmID {
	case ED25519AlgorithmID:
		return ED25519GeneratePrivateKey()
	default:
		return jwk.JWK{}, fmt.Errorf("unsupported algorithm: %s", algorithmID)
	}
}

func GetPublicKey(privateKey jwk.JWK) jwk.JWK {
	return jwk.JWK{
		KTY: privateKey.KTY,
		CRV: privateKey.CRV,
		X:   privateKey.X,
	}
}

func Sign(payload []byte, privateKey jwk.JWK) ([]byte, error) {
	if privateKey.D == "" {
		return nil, errors.New("d must be set")
	}

	switch privateKey.CRV {
	case ED25519JWACurve:
		return ED25519Sign(payload, privateKey)
	default:
		return nil, fmt.Errorf("unsupported curve: %s", privateKey.CRV)
	}
}

func Verify(payload []byte, signature []byte, publicKey jwk.JWK) (bool, error) {
	switch publicKey.CRV {
	case ED25519JWACurve:
		return ED25519Verify(payload, signature, publicKey)
	default:
		return false, fmt.Errorf("unsupported curve: %s", publicKey.CRV)
	}
}

func GetJWA(jwk jwk.JWK) (string, error) {
	return JWA, nil
}

func SupportsAlgorithmID(id string) bool {
	return AlgorithmIDs[id]
}
