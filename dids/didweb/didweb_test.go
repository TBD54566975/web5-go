package didweb_test

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/dids/did"
	"github.com/tbd54566975/web5-go/dids/didcore"
	"github.com/tbd54566975/web5-go/dids/didweb"
)

func TestCreate(t *testing.T) {
	bearerDID, err := didweb.Create("localhost:8080")
	assert.NoError(t, err)

	assert.NotEqual(t, didcore.Document{}, bearerDID.Document)

	document := bearerDID.Document
	assert.Equal(t, "did:web:localhost%3A8080", document.ID)
	assert.Equal(t, 1, len(document.VerificationMethod))
}

func TestCreate_WithOptions(t *testing.T) {
	bearerDID, err := didweb.Create(
		"localhost:8080",
		didweb.Service("pfi", "PFI", "http://localhost:8080/tbdex"),
		didweb.Service("idv", "IDV", "http://localhost:8080/idv"),
		didweb.AlsoKnownAs("did:example:123"),
		didweb.Controllers("did:example:123"),
	)

	assert.NoError(t, err)
	assert.NotEqual(t, did.BearerDID{}, bearerDID)

	document := bearerDID.Document
	assert.Equal(t, 2, len(document.Service))

	pfisvc := document.Service[0]
	assert.NotEqual(t, didcore.Service{}, *pfisvc)
	assert.Equal(t, "#pfi", pfisvc.ID)
	assert.Equal(t, "PFI", pfisvc.Type)
	assert.Equal(t, "http://localhost:8080/tbdex", pfisvc.ServiceEndpoint)

	idvsvc := document.Service[1]
	assert.NotEqual(t, didcore.Service{}, *idvsvc)
	assert.Equal(t, "#idv", idvsvc.ID)
	assert.Equal(t, "IDV", idvsvc.Type)
	assert.Equal(t, "http://localhost:8080/idv", idvsvc.ServiceEndpoint)

	assert.Equal(t, "did:example:123", document.AlsoKnownAs[0])
	assert.Equal(t, "did:example:123", document.Controller[0])

}

func TestDecodeID(t *testing.T) {
	portAndPathCase := didweb.DecodeID("localhost%3A8080:something")
	assert.Equal(t, "https://localhost:8080/something/did.json", portAndPathCase)

	wellKnownCase := didweb.DecodeID("localhost")
	assert.Equal(t, "https://localhost/.well-known/did.json", wellKnownCase)
}
