package eddsa_test

import (
	"encoding/hex"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/crypto/dsa/eddsa"
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
