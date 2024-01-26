package dids_test

import (
	"testing"

	"github.com/tbd54566975/web5-go/dids"
	"github.com/tbd54566975/web5-go/jwk"
	"github.com/tbd54566975/web5-go/jws"
)

func Test_ToKeys(t *testing.T) {
	did, err := dids.NewDIDJWK()
	if err != nil {
		t.Fatal(err)
	}

	portableDID, err := did.ToKeys()
	if err != nil {
		t.Fatal(err)
	}

	if portableDID.URI != did.URI {
		t.Errorf("expected uri %s, got %s", did.URI, portableDID.URI)
	}

	if len(portableDID.VerificationMethod) != 1 {
		t.Errorf("expected 1 key, got %d", len(portableDID.VerificationMethod))
	}

	if (portableDID.VerificationMethod[0].PublicKeyJWK == jwk.JWK{}) {
		t.Errorf("expected publicKeyJwk to not be empty")
	}

	if (portableDID.VerificationMethod[0].PrivateKeyJWK == jwk.JWK{}) {
		t.Errorf("expected publicKeyJwk to not be empty")
	}
}

func TestBearerDIDFromKeys(t *testing.T) {
	did, err := dids.NewDIDJWK()
	if err != nil {
		t.Errorf("failed to create DID %v", err)
	}

	portableDID, err := did.ToKeys()
	if err != nil {
		t.Errorf("failed to export DID")
	}

	importedDID, err := dids.BearerDIDFromKeys(portableDID)
	if err != nil {
		t.Errorf("failed to import DID %v", err)
	}

	compactJWS, err := jws.Sign("hi", did)
	if err != nil {
		t.Errorf("failed to sign with did: %v", err)
	}

	compactJWSAgane, err := jws.Sign("hi", importedDID)
	if err != nil {
		t.Errorf("failed to sign with imported did: %v", err)
	}

	if compactJWS != compactJWSAgane {
		t.Errorf("failed to produce same signature with imported did")
	}
}
