package jws_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/dids/didjwk"
	"github.com/tbd54566975/web5-go/jws"
)

func TestSign(t *testing.T) {
	did, err := didjwk.Create()
	assert.NoError(t, err)

	payload := map[string]interface{}{"hello": "world"}
	compactJWS, err := jws.Sign(payload, did)
	assert.NoError(t, err)

	assert.True(t, compactJWS != "", "expected signature to be non-empty")

	parts := strings.Split(compactJWS, ".")
	assert.Equal(t, 3, len(parts), "expected 3 parts in compact JWS")
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

		assert.Error(t, err, "expected verification error. vector: %s", vector)
		assert.False(t, ok, "expected verification !ok. vector %s", vector)
	}
}

func TestVerify_ok(t *testing.T) {
	did, err := didjwk.Create()
	assert.NoError(t, err)

	payloadJSON := map[string]interface{}{"hello": "world"}
	compactJWS, err := jws.Sign(payloadJSON, did)

	assert.NoError(t, err)

	ok, err := jws.Verify(compactJWS)
	assert.NoError(t, err)

	assert.True(t, ok, "expected verification ok")
}
