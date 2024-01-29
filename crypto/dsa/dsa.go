package dsa

import (
	"fmt"

	"github.com/tbd54566975/web5-go/crypto/dsa/ecdsa"
	"github.com/tbd54566975/web5-go/crypto/dsa/eddsa"
	"github.com/tbd54566975/web5-go/jwk"
)

var AlgorithmID = struct {
	SECP256K1 string
	ED25519   string
}{
	SECP256K1: ecdsa.SECP256K1AlgorithmID,
	ED25519:   eddsa.ED25519AlgorithmID,
}

// GeneratePrivateKey generates a private key using the algorithm specified by algorithmID.
func GeneratePrivateKey(algorithmID string) (jwk.JWK, error) {
	if ecdsa.SupportsAlgorithmID(algorithmID) {
		return ecdsa.GeneratePrivateKey(algorithmID)
	} else if eddsa.SupportsAlgorithmID(algorithmID) {
		return eddsa.GeneratePrivateKey(algorithmID)
	} else {
		return jwk.JWK{}, fmt.Errorf("unsupported algorithm: %s", algorithmID)
	}
}

// GetPublicKey returns the public key corresponding to the given private key.
func GetPublicKey(privateKey jwk.JWK) jwk.JWK {
	switch privateKey.KTY {
	case ecdsa.KeyType:
		return ecdsa.GetPublicKey(privateKey)
	case eddsa.KeyType:
		return eddsa.GetPublicKey(privateKey)
	default:
		return jwk.JWK{}
	}
}

// Sign signs the payload using the given private key.
func Sign(payload []byte, jwk jwk.JWK) ([]byte, error) {
	switch jwk.KTY {
	case ecdsa.KeyType:
		return ecdsa.Sign(payload, jwk)
	case eddsa.KeyType:
		return eddsa.Sign(payload, jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.KTY)
	}
}

// Verify verifies the signature of the payload using the given public key.
func Verify(payload []byte, signature []byte, jwk jwk.JWK) (bool, error) {
	switch jwk.KTY {
	case ecdsa.KeyType:
		return ecdsa.Verify(payload, signature, jwk)
	case eddsa.KeyType:
		return eddsa.Verify(payload, signature, jwk)
	default:
		return false, fmt.Errorf("unsupported key type: %s", jwk.KTY)
	}
}

// GetJWA returns the JWA (JSON Web Algorithm) algorithm corresponding to the given key.
func GetJWA(jwk jwk.JWK) (string, error) {
	switch jwk.KTY {
	case ecdsa.KeyType:
		return ecdsa.GetJWA(jwk)
	case eddsa.KeyType:
		return eddsa.GetJWA(jwk)
	default:
		return "", fmt.Errorf("unsupported key type: %s", jwk.KTY)
	}
}
