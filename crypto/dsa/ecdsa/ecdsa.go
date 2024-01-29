package ecdsa

import (
	"fmt"

	"github.com/tbd54566975/web5-go/jwk"
)

const (
	KeyType = "EC"
)

var algorithmIDs = map[string]bool{
	SECP256K1AlgorithmID: true,
}

func GeneratePrivateKey(algorithmID string) (jwk.JWK, error) {
	var privateKey jwk.JWK
	var err error

	switch algorithmID {
	case SECP256K1AlgorithmID:
		privateKey, err = SECP256K1GeneratePrivateKey()
	default:
		err = fmt.Errorf("unsupported algorithm: %s", algorithmID)
	}

	return privateKey, err
}

func GetPublicKey(privateKey jwk.JWK) jwk.JWK {
	return jwk.JWK{
		KTY: privateKey.KTY,
		CRV: privateKey.CRV,
		X:   privateKey.X,
		Y:   privateKey.Y,
	}
}

func Sign(payload []byte, privateKey jwk.JWK) ([]byte, error) {
	if privateKey.D == "" {
		return nil, fmt.Errorf("d must be set")
	}

	var signature []byte
	var err error

	switch privateKey.CRV {
	case SECP256K1JWACurve:
		signature, err = SECP256K1Sign(payload, privateKey)
	default:
		err = fmt.Errorf("unsupported curve: %s", privateKey.CRV)
	}

	return signature, err
}

func Verify(payload []byte, signature []byte, publicKey jwk.JWK) (bool, error) {
	var valid bool
	var err error

	switch publicKey.CRV {
	case SECP256K1JWACurve:
		valid, err = SECP256K1Verify(payload, signature, publicKey)
	default:
		err = fmt.Errorf("unsupported curve: %s", publicKey.CRV)
	}

	return valid, err
}

func GetJWA(jwk jwk.JWK) (string, error) {
	switch jwk.CRV {
	case SECP256K1JWACurve:
		return SECP256K1JWA, nil
	default:
		return "", fmt.Errorf("unsupported curve: %s", jwk.CRV)
	}
}

func SupportsAlgorithmID(id string) bool {
	return algorithmIDs[id]
}
