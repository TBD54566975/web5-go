package eddsa_test

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/crypto/dsa/eddsa"
	"github.com/tbd54566975/web5-go/jwk"
)

func TestED25519BytesToPublicKey_Bad(t *testing.T) {
	publicKeyBytes := []byte{0x00, 0x01, 0x02, 0x03}
	_, err := eddsa.ED25519BytesToPublicKey(publicKeyBytes)
	assert.Error(t, err)
}

func TestED25519BytesToPublicKey_Good(t *testing.T) {
	// vector taken from https://github.com/TBD54566975/web5-js/blob/dids-new-crypto/packages/crypto/tests/fixtures/test-vectors/ed25519/bytes-to-public-key.json
	pubKeyHex := "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa"
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	assert.NoError(t, err)

	jwk, err := eddsa.ED25519BytesToPublicKey(pubKeyBytes)
	assert.NoError(t, err)

	assert.Equal(t, jwk.KTY, eddsa.KeyType)
	assert.Equal(t, jwk.CRV, eddsa.ED25519JWACurve)
	assert.Equal(t, jwk.X, "fU0Of2FTpptiQrUiq77mhf2kQg-INLEIw72uNp71Sfo")
}

func TestED25519PublicKeyToBytes(t *testing.T) {
	// vector taken from: https://github.com/TBD54566975/web5-spec/blob/main/test-vectors/crypto_ed25519/sign.json
	jwk := jwk.JWK{
		KTY: "OKP",
		CRV: eddsa.ED25519JWACurve,
		X:   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
	}

	pubKeyBytes, err := eddsa.ED25519PublicKeyToBytes(jwk)
	assert.NoError(t, err)

	pubKeyB64URL := base64.RawURLEncoding.EncodeToString(pubKeyBytes)
	assert.Equal(t, jwk.X, pubKeyB64URL)
}

func TestED25519PublicKeyToBytes_Bad(t *testing.T) {
	vectors := []jwk.JWK{
		{
			KTY: "OKP",
			CRV: eddsa.ED25519JWACurve,
		},
		{
			KTY: "OKP",
			CRV: eddsa.ED25519JWACurve,
			X:   "=/---",
		},
	}

	for _, jwk := range vectors {
		pubKeyBytes, err := eddsa.ED25519PublicKeyToBytes(jwk)
		assert.Error(t, err)

		assert.Equal(t, nil, pubKeyBytes)
	}
}
