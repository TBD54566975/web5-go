package dids

import "testing"

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

	if len(doc.VerificationMethod) != 1 {
		t.Errorf("expected 1 verification method, got %d", len(doc.VerificationMethod))
	}

	if len(doc.Authentication) != 1 {
		t.Errorf("expected 1 authentication method, got %d", len(doc.Authentication))
	}

	if doc.Authentication[0] != vm.ID {
		t.Errorf("expected authentication method %s, got %s", vm.ID, doc.Authentication[0])
	}
}
