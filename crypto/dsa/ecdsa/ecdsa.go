package ecdsa

import (
	"errors"
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
	switch algorithmID {
	case SECP256K1AlgorithmID:
		return SECP256K1GeneratePrivateKey()
	default:
		return jwk.JWK{}, fmt.Errorf("unsupported algorithm: %s", algorithmID)
	}
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
		return nil, errors.New("d must be set")
	}

	switch privateKey.CRV {
	case SECP256K1JWACurve:
		return SECP256K1Sign(payload, privateKey)
	default:
		return nil, fmt.Errorf("unsupported curve: %s", privateKey.CRV)
	}
}

func Verify(payload []byte, signature []byte, publicKey jwk.JWK) (bool, error) {
	switch publicKey.CRV {
	case SECP256K1JWACurve:
		return SECP256K1Verify(payload, signature, publicKey)
	default:
		return false, fmt.Errorf("unsupported curve: %s", publicKey.CRV)
	}
}

func GetJWA(jwk jwk.JWK) (string, error) {
	switch jwk.CRV {
	case SECP256K1JWACurve:
		return SECP256K1JWA, nil
	default:
		return "", fmt.Errorf("unsupported curve: %s", jwk.CRV)
	}
}

func BytesToPublicKey(algorithmID string, input []byte) (jwk.JWK, error) {
	switch algorithmID {
	case SECP256K1AlgorithmID:
		return SECP256K1BytesToPublicKey(input)
	default:
		return jwk.JWK{}, fmt.Errorf("unsupported algorithm: %s", algorithmID)
	}
}

func PublicKeyToBytes(publicKey jwk.JWK) ([]byte, error) {
	switch publicKey.CRV {
	case SECP256K1JWACurve:
		return SECP256K1PublicKeyToBytes(publicKey)
	default:
		return nil, fmt.Errorf("unsupported curve: %s", publicKey.CRV)
	}
}

func SupportsAlgorithmID(id string) bool {
	return algorithmIDs[id]
}
