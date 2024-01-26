package ecdsa

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	_secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/tbd54566975/web5-go/jwk"
)

const (
	SECP256K1JWA         string = "ES256K"
	SECP256K1JWACurve    string = "secp256k1"
	SECP256K1AlgorithmID string = SECP256K1JWACurve
)

func SECP256K1GeneratePrivateKey() (jwk.JWK, error) {
	keyPair, err := _secp256k1.GeneratePrivateKey()
	if err != nil {
		return jwk.JWK{}, fmt.Errorf("failed to generate private key: %w", err)
	}

	dBytes := keyPair.Key.Bytes()
	pubKey := keyPair.PubKey()
	xBytes := pubKey.X().Bytes()
	yBytes := pubKey.Y().Bytes()

	privateKey := jwk.JWK{
		KTY: KeyType,
		CRV: SECP256K1JWACurve,
		D:   base64.RawURLEncoding.EncodeToString(dBytes[:]),
		X:   base64.RawURLEncoding.EncodeToString(xBytes),
		Y:   base64.RawURLEncoding.EncodeToString(yBytes),
	}

	return privateKey, nil
}

func SECP256K1Sign(payload []byte, privateKey jwk.JWK) ([]byte, error) {
	privateKeyBytes, err := base64.RawURLEncoding.DecodeString(privateKey.D)
	if err != nil {
		return nil, fmt.Errorf("failed to decode d %w", err)
	}

	key := _secp256k1.PrivKeyFromBytes(privateKeyBytes)

	hash := sha256.Sum256(payload)
	signature := ecdsa.SignCompact(key, hash[:], false)[1:]

	return signature, nil
}

func SECP256K1Verify(payload []byte, signature []byte, publicKey jwk.JWK) (bool, error) {
	if publicKey.X == "" || publicKey.Y == "" {
		return false, fmt.Errorf("x and y must be set")
	}

	hash := sha256.Sum256(payload)

	x, _ := base64.RawURLEncoding.DecodeString(publicKey.X)
	y, _ := base64.RawURLEncoding.DecodeString(publicKey.Y)

	keyBytes := []byte{0x04}
	keyBytes = append(keyBytes, x...)
	keyBytes = append(keyBytes, y...)

	key, err := _secp256k1.ParsePubKey(keyBytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %w", err)
	}

	r := new(_secp256k1.ModNScalar)
	r.SetByteSlice(signature[:32])

	s := new(_secp256k1.ModNScalar)
	s.SetByteSlice(signature[32:])

	sig := ecdsa.NewSignature(r, s)
	legit := sig.Verify(hash[:], key)

	return legit, nil
}
