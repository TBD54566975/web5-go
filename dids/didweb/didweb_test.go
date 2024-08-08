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

	did := bearerDID.DID
	assert.Equal(t, "web", did.Method)
	assert.Equal(t, "localhost%3A8080", did.ID)
	assert.Equal(t, "did:web:localhost%3A8080", did.URI)
	assert.Equal(t, "did:web:localhost%3A8080", did.URL())
}

func TestParse(t *testing.T) {
	bearerDID, err := didweb.Create("localhost:8080")
	assert.NoError(t, err)
	original := bearerDID.DID

	// URI -> Parse
	parseURIDID, err := did.Parse(original.URI)
	assert.NoError(t, err)
	assert.Equal(t, original, parseURIDID)

	// String -> Parse
	parseStringDID, err := did.Parse(original.String())
	assert.NoError(t, err)
	assert.Equal(t, original, parseStringDID)

	// Value -> Scan
	var scanDID did.DID
	value, err := original.Value()
	assert.NoError(t, err)
	err = scanDID.Scan(value)
	assert.NoError(t, err)
	assert.Equal(t, original, scanDID)
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
	assert.NotEqual(t, didcore.Service{}, pfisvc)
	assert.Equal(t, "#pfi", pfisvc.ID)
	assert.Equal(t, "PFI", pfisvc.Type)
	assert.Equal(t, "http://localhost:8080/tbdex", pfisvc.ServiceEndpoint[0])

	idvsvc := document.Service[1]
	assert.NotEqual(t, didcore.Service{}, idvsvc)
	assert.Equal(t, "#idv", idvsvc.ID)
	assert.Equal(t, "IDV", idvsvc.Type)
	assert.Equal(t, "http://localhost:8080/idv", idvsvc.ServiceEndpoint[0])

	assert.Equal(t, "did:example:123", document.AlsoKnownAs[0])
	assert.Equal(t, "did:example:123", document.Controller[0])

	assert.Equal(t, 1, len(document.VerificationMethod))
	assert.Contains(t, document.VerificationMethod[0].ID, document.ID)

}

func TestTransformID(t *testing.T) {
	var vectors = []struct {
		input  string
		output string
		err    bool
	}{
		{
			input:  "example.com:user:alice",
			output: "https://example.com/user/alice/did.json",
			err:    false,
		},
		{
			input:  "localhost%3A8080:user:alice",
			output: "http://localhost:8080/user/alice/did.json",
			err:    false,
		},
		{
			input:  "192.168.1.100%3A8892:ingress",
			output: "http://192.168.1.100:8892/ingress/did.json",
			err:    false,
		},
		{
			input:  "www.linkedin.com",
			output: "https://www.linkedin.com/.well-known/did.json",
			err:    false,
		},
	}

	for _, v := range vectors {
		t.Run(v.input, func(t *testing.T) {
			output, err := didweb.TransformID(v.input)
			assert.NoError(t, err)
			assert.Equal(t, v.output, output)
		})
	}
}
