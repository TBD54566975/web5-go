package eddsa

import (
	_ed25519 "crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/tbd54566975/web5-go/common"
	"github.com/tbd54566975/web5-go/jwk"
)

const (
	ED25519JWACurve    string = "Ed25519"
	ED25519AlgorithmID string = ED25519JWACurve
)

func ED25519GeneratePrivateKey() (jwk.JWK, error) {
	publicKey, privateKey, err := _ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return jwk.JWK{}, err
	}

	privKeyJwk := jwk.JWK{
		KTY: KeyType,
		CRV: ED25519JWACurve,
		D:   common.Base64UrlEncodeNoPadding(privateKey),
		X:   common.Base64UrlEncodeNoPadding(publicKey),
	}

	return privKeyJwk, nil
}

func ED25519Sign(payload []byte, privateKey jwk.JWK) ([]byte, error) {
	privateKeyBytes, err := common.Base64UrlDecodeNoPadding(privateKey.D)
	if err != nil {
		return nil, fmt.Errorf("failed to decode d %w", err)
	}

	signature := _ed25519.Sign(privateKeyBytes, payload)
	return signature, nil
}

func ED25519Verify(payload []byte, signature []byte, publicKey jwk.JWK) (bool, error) {
	publicKeyBytes, err := common.Base64UrlDecodeNoPadding(publicKey.X)
	if err != nil {
		return false, err
	}

	legit := _ed25519.Verify(publicKeyBytes, payload, signature)
	return legit, nil
}
