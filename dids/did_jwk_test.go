package dids

import (
	"testing"

	"github.com/tbd54566975/web5-go/jwk"
)

func TestNewDIDJWK(t *testing.T) {
	did, err := NewDIDJWK()
	if err != nil {
		t.Errorf("failed to create did: %s", err.Error())
	}

	if did.Method != "jwk" {
		t.Errorf("expected method to be jwk, got %s", did.Method)
	}

	if did.Fragment != "" {
		t.Errorf("expected fragment to be empty, got %s", did.Fragment)
	}

	if did.Path != "" {
		t.Errorf("expected path to be empty, got %s", did.Path)
	}

	if did.Query != "" {
		t.Errorf("expected query to be empty, got %s", did.Query)
	}

	if did.ID == "" {
		t.Errorf("expected id to be non-empty")
	}

	if did.URI != "did:jwk:"+did.ID {
		t.Errorf("expected uri to be did:jwk:%s, got %s", did.ID, did.URI)
	}
}

func TestResolveDIDJWK(t *testing.T) {
	result := ResolveDIDJWK("did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1icHJpbnQ6c2hhLTI1NjpGZk1iek9qTW1RNGVmVDZrdndUSUpqZWxUcWpsMHhqRUlXUTJxb2JzUk1NIiwia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImFsZyI6IkVkRFNBIiwieCI6IkFOUmpIX3p4Y0tCeHNqUlBVdHpSYnA3RlNWTEtKWFE5QVBYOU1QMWo3azQifQ")
	if result.GetError() != "" {
		t.Errorf("expected no error, got %s", result.GetError())
	}

	if len(result.Document.VerificationMethod) == 0 {
		t.Errorf("expected verification method to be non-empty")
	}

	if result.Document.VerificationMethod[0] == (VerificationMethod{}) {
		t.Errorf("expected verification method to be non-empty")
	}

	if result.Document.VerificationMethod[0].PublicKeyJwk == (jwk.JWK{}) {
		t.Errorf("expected publicKeyJwk to be non-empty")
	}

	if len(result.Document.Authentication) == 0 {
		t.Errorf("expected authentication to be non-empty")
	}

	if len(result.Document.AssertionMethod) == 0 {
		t.Errorf("expected assertion method to be non-empty")
	}
}
