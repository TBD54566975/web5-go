package did_test

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/crypto/dsa"
	"github.com/tbd54566975/web5-go/dids/did"
	"github.com/tbd54566975/web5-go/dids/didcore"
	"github.com/tbd54566975/web5-go/dids/didjwk"
	"github.com/tbd54566975/web5-go/jwk"
	"github.com/tbd54566975/web5-go/jws"
)

func TestToPortableDID(t *testing.T) {
	did, err := didjwk.Create()
	assert.NoError(t, err)

	portableDID, err := did.ToPortableDID()
	assert.NoError(t, err)

	assert.Equal[string](t, did.URI, portableDID.URI)
	assert.True(t, len(portableDID.PrivateKeys) == 1, "expected 1 key")

	key := portableDID.PrivateKeys[0]

	assert.NotEqual(t, jwk.JWK{}, key, "expected key to not be empty")
}

func TestFromPortableDID(t *testing.T) {
	bearerDID, err := didjwk.Create()
	assert.NoError(t, err)

	portableDID, err := bearerDID.ToPortableDID()
	assert.NoError(t, err)

	importedDID, err := did.FromPortableDID(portableDID)
	assert.NoError(t, err)

	compactJWS, err := jws.Sign("hi", bearerDID)
	assert.NoError(t, err)

	compactJWSAgane, err := jws.Sign("hi", importedDID)
	assert.NoError(t, err)

	assert.Equal[string](t, compactJWS, compactJWSAgane, "failed to produce same signature with imported did")
}

func TestGetSigner(t *testing.T) {
	bearerDID, err := didjwk.Create()
	assert.NoError(t, err)

	sign, vm, err := bearerDID.GetSigner(nil)
	assert.NoError(t, err)

	assert.NotEqual(t, vm, didcore.VerificationMethod{}, "expected verification method to not be empty")

	payload := []byte("hi")
	signature, err := sign(payload)
	assert.NoError(t, err)

	legit, err := dsa.Verify(payload, signature, *vm.PublicKeyJwk)
	assert.NoError(t, err)

	assert.True(t, legit, "expected signature to be valid")
}
