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
}

func TestCreate_WithServiceOption(t *testing.T) {
	bearerDID, err := didweb.Create(
		"localhost:8080",
		didweb.Service("pfi", "PFI", "http://localhost:8080"),
	)

	assert.NoError(t, err)
	assert.NotEqual(t, did.BearerDID{}, bearerDID)

	document := bearerDID.Document
	assert.Equal(t, 1, len(document.Service))

	svc := document.Service[0]
	assert.NotEqual(t, didcore.Service{}, *svc)
	assert.Equal(t, "pfi", svc.ID)
	assert.Equal(t, "PFI", svc.Type)
	assert.Equal(t, "http://localhost:8080", svc.ServiceEndpoint)
}
