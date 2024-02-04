package did_test

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/dids/did"
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

	assert.NotEqual(t, key, jwk.JWK{}, "expected key to not be empty")
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
