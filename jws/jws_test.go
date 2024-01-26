package jws_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/tbd54566975/web5-go/dids"
	"github.com/tbd54566975/web5-go/jws"
)

func TestSign(t *testing.T) {
	did, err := dids.NewDIDJWK()
	if err != nil {
		t.Errorf("failed to create did: %v", err.Error())
	}

	payload := map[string]interface{}{"hello": "world"}
	compactJWS, err := jws.Sign(payload, did)
	if err != nil {
		t.Errorf("failed to sign: %v", err.Error())
	}

	if compactJWS == "" {
		t.Errorf("signature is empty: %v", err.Error())
	}

	parts := strings.Split(compactJWS, ".")
	if len(parts) != 3 {
		t.Errorf("invalid jws format. expected 3 parts. got %d", len(parts))
	}
}

func TestVerify_bad(t *testing.T) {
	badHeader := base64.RawURLEncoding.EncodeToString([]byte("hehe"))
	okHeader := jws.Header{ALG: "ES256K", KID: "did:web:abc#key-1"}.Base64UrlEncode()

	okPayloadJSON := map[string]interface{}{"hello": "world"}
	okPayloadBytes, _ := json.Marshal(okPayloadJSON)
	okPayload := base64.RawURLEncoding.EncodeToString(okPayloadBytes)

	badSignature := base64.RawURLEncoding.EncodeToString([]byte("hehe"))

	vectors := []string{
		"",
		"..",
		"a.b.c",
		fmt.Sprintf("%s.%s.%s", badHeader, badHeader, badHeader),
		fmt.Sprintf("%s.%s.%s", okHeader, okPayload, badSignature),
	}

	for _, vector := range vectors {
		ok, err := jws.Verify(vector)
		if err == nil {
			t.Errorf("expected verification error. vector: %s", vector)
		}

		fmt.Printf("vector: %s, err: %v\n", vector, err)

		if ok {
			t.Errorf("expected verification !ok. vector %s", vector)
		}
	}
}

func TestVerify_ok(t *testing.T) {
	did, err := dids.NewDIDJWK()
	if err != nil {
		t.Errorf("failed to create did: %v", err.Error())
	}

	payloadJSON := map[string]interface{}{"hello": "world"}
	compactJWS, err := jws.Sign(payloadJSON, did)

	if err != nil {
		t.Errorf("failed to sign: %v", err.Error())
	}

	ok, err := jws.Verify(compactJWS)
	if err != nil {
		t.Errorf("failed to verify: %v", err.Error())
	}

	if !ok {
		t.Errorf("expected verification ok")
	}
}
