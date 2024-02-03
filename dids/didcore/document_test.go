package didcore

import (
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestAddVerificationMethod(t *testing.T) {
	doc := Document{
		Context: "https://www.w3.org/ns/did/v1",
		ID:      "did:example:123456789abcdefghi",
	}

	vm := VerificationMethod{
		ID:         "did:example:123456789abcdefghi#keys-1",
		Type:       "Ed25519VerificationKey2018",
		Controller: "did:example:123456789abcdefghi",
	}

	doc.AddVerificationMethod(vm, Purposes("authentication"))

	assert.Equal(t, len(doc.VerificationMethod), 1)
	assert.Equal(t, len(doc.Authentication), 1)
	assert.Equal(t, doc.Authentication[0], vm.ID)
}
