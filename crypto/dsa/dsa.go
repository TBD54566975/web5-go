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

func GeneratePrivateKey(algorithmID string) (jwk.JWK, error) {

	var privateKey jwk.JWK
	var err error

	if ecdsa.SupportsAlgorithmID(algorithmID) {
		privateKey, err = ecdsa.GeneratePrivateKey(algorithmID)
	} else if eddsa.SupportsAlgorithmID(algorithmID) {
		privateKey, err = eddsa.GeneratePrivateKey(algorithmID)
	} else {
		err = fmt.Errorf("unsupported algorithm: %s", algorithmID)
	}

	return privateKey, err
}

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

func Sign(payload []byte, jwk jwk.JWK) ([]byte, error) {
	var err error
	var signature []byte

	switch jwk.KTY {
	case ecdsa.KeyType:
		signature, err = ecdsa.Sign(payload, jwk)
	case eddsa.KeyType:
		signature, err = eddsa.Sign(payload, jwk)
	default:
		err = fmt.Errorf("unsupported key type: %s", jwk.KTY)
	}

	return signature, err
}

func Verify(payload []byte, signature []byte, jwk jwk.JWK) (bool, error) {
	var err error
	var valid bool

	switch jwk.KTY {
	case ecdsa.KeyType:
		valid, err = ecdsa.Verify(payload, signature, jwk)
	case eddsa.KeyType:
		valid, err = eddsa.Verify(payload, signature, jwk)
	default:
		err = fmt.Errorf("unsupported key type: %s", jwk.KTY)
	}

	return valid, err
}

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
