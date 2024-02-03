package did_test

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/dids/did"
	"github.com/tbd54566975/web5-go/dids/didjwk"
	"github.com/tbd54566975/web5-go/jwk"
	"github.com/tbd54566975/web5-go/jws"
)

func Test_ToKeys(t *testing.T) {
	did, err := didjwk.Create()
	assert.NoError(t, err)

	portableDID, err := did.ToKeys()
	assert.NoError(t, err)

	assert.Equal[string](t, did.URI, portableDID.URI)
	assert.True(t, len(portableDID.VerificationMethod) == 1, "expected 1 key")

	vm := portableDID.VerificationMethod[0]

	assert.NotEqual(t, *vm.PublicKeyJWK, jwk.JWK{}, "expected publicKeyJwk to not be empty")
	assert.NotEqual(t, vm.PrivateKeyJWK, jwk.JWK{}, "expected privateKeyJWK to not be empty")
}

func TestBearerDIDFromKeys(t *testing.T) {
	bearerDID, err := didjwk.Create()
	assert.NoError(t, err)

	portableDID, err := bearerDID.ToKeys()
	assert.NoError(t, err)

	importedDID, err := did.BearerDIDFromKeys(portableDID)
	assert.NoError(t, err)

	compactJWS, err := jws.Sign("hi", bearerDID)
	assert.NoError(t, err)

	compactJWSAgane, err := jws.Sign("hi", importedDID)
	assert.NoError(t, err)

	assert.Equal[string](t, compactJWS, compactJWSAgane, "failed to produce same signature with imported did")
}
