package didcore_test

import (
	"encoding/json"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/dids/didcore"
)

func TestAddVerificationMethod(t *testing.T) {
	doc := didcore.Document{
		Context: "https://www.w3.org/ns/did/v1",
		ID:      "did:example:123456789abcdefghi",
	}

	vm := didcore.VerificationMethod{
		ID:         "did:example:123456789abcdefghi#keys-1",
		Type:       "Ed25519VerificationKey2018",
		Controller: "did:example:123456789abcdefghi",
	}

	doc.AddVerificationMethod(vm, didcore.Purposes("authentication"))

	assert.Equal(t, 1, len(doc.VerificationMethod))
	assert.Equal(t, 1, len(doc.Authentication))
	assert.Equal(t, vm.ID, doc.Authentication[0])
}

func TestWoo(t *testing.T) {
	doc := didcore.Document{
		ID: "did:example:123456789abcdefghi",
	}

	doc.AddVerificationMethod(didcore.VerificationMethod{
		ID:         "did:example:123456789abcdefghi#keys-1",
		Type:       "Ed25519VerificationKey2018",
		Controller: "did:example:123456789abcdefghi",
	}, didcore.Purposes("authentication"))

	vm, err := doc.SelectVerificationMethod(didcore.Purpose("authentication"))
	assert.NoError(t, err)
	assert.Equal(t, "did:example:123456789abcdefghi#keys-1", vm.ID)
}

func TestUnmarshal_ContextString(t *testing.T) {
	var doc didcore.Document
	err := json.Unmarshal([]byte(`{
        "@context": "https://www.w3.org/ns/did/v1"
    }`), &doc)
	assert.NoError(t, err)
	assert.Equal(t, "https://www.w3.org/ns/did/v1", doc.Context)
}

func TestUnmarshal_ContextStringArray(t *testing.T) {
	var doc didcore.Document
	err := json.Unmarshal([]byte(`{
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://www.w3.org/ns/did/v1"
        ]
    }`), &doc)
	assert.NoError(t, err)
	context, ok := doc.Context.([]didcore.Context)
	assert.True(t, ok)
	assert.Equal(t, []didcore.Context{"https://www.w3.org/ns/did/v1", "https://www.w3.org/ns/did/v1"}, context)
}

func TestUnmarshal_ContextMixedTypes(t *testing.T) {
	var doc didcore.Document
	err := json.Unmarshal([]byte(`{
        "@context": [
            "https://www.w3.org/ns/did/v1",
            { "@base": "did:web:www.linkedin.com" }
        ]
    }`), &doc)
	assert.NoError(t, err)
	context, ok := doc.Context.([]didcore.Context)
	assert.True(t, ok)
	assert.Equal(t, []didcore.Context{
		"https://www.w3.org/ns/did/v1",
		map[string]interface{}{"@base": "did:web:www.linkedin.com"},
	}, context)
}
