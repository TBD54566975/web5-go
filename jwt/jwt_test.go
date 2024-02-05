package jwt_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/dids/didjwk"
	"github.com/tbd54566975/web5-go/jws"
	"github.com/tbd54566975/web5-go/jwt"
)

func TestClaims_MarshalJSON(t *testing.T) {
	claims := jwt.Claims{
		Issuer: "issuer",
		Misc:   map[string]interface{}{"foo": "bar"},
	}

	b, err := json.Marshal(&claims)
	assert.NoError(t, err)

	obj := make(map[string]interface{})
	json.Unmarshal(b, &obj)

	assert.Equal(t, obj["iss"], "issuer")
	assert.False(t, obj["foo"] == nil)
}

func TestClaims_UnmarshalJSON(t *testing.T) {
	claims := jwt.Claims{
		Issuer: "issuer",
		Misc:   map[string]interface{}{"foo": "bar"},
	}

	b, err := json.Marshal(&claims)
	assert.NoError(t, err)

	claimsAgane := jwt.Claims{}
	json.Unmarshal(b, &claimsAgane)

	assert.Equal(t, claims.Issuer, claimsAgane.Issuer)
	assert.False(t, claimsAgane.Misc["foo"] == nil)
	assert.Equal(t, claimsAgane.Misc["foo"], claims.Misc["foo"])
}

func TestSign(t *testing.T) {
	did, err := didjwk.Create()
	assert.NoError(t, err)

	claims := jwt.Claims{
		Issuer: did.ID,
		Misc:   map[string]interface{}{"c_nonce": "abcd123"},
	}

	jwt, err := jwt.Sign(claims, did)
	assert.NoError(t, err)

	assert.False(t, jwt == "", "expected jwt to not be empty")
}

func TestVerify(t *testing.T) {
	did, err := didjwk.Create()
	assert.NoError(t, err)

	claims := jwt.Claims{
		Issuer: did.ID,
		Misc:   map[string]interface{}{"c_nonce": "abcd123"},
	}

	signedJwt, err := jwt.Sign(claims, did)
	assert.NoError(t, err)

	assert.False(t, signedJwt == "", "expected jwt to not be empty")

	verified, err := jwt.Verify(signedJwt)
	assert.NoError(t, err)

	assert.True(t, verified, "expected verified")
}

func TestVerify_BadClaims(t *testing.T) {
	okHeader := jws.Header{ALG: "ES256K", KID: "did:web:abc#key-1"}.Base64UrlEncode()
	input := fmt.Sprintf("%s.%s.%s", okHeader, "hehe", "hehe")

	verified, err := jwt.Verify(input)
	assert.Error(t, err)
	assert.False(t, verified, "expected !verified")
}

func TestDecodeJWTClaims(t *testing.T) {
	did, err := didjwk.Create()
	assert.NoError(t, err)

	nonce := "abcd123"
	claims := jwt.Claims{
		Issuer: did.ID,
		Misc:   map[string]interface{}{"c_nonce": nonce},
	}

	signedJwt, err := jwt.Sign(claims, did)
	assert.NoError(t, err)

	parts := strings.Split(signedJwt, ".")
	assert.Equal(t, 3, len(parts), "expected 3 parts in JWT")
	base64UrlEncodedClaims := parts[1]

	decodedClaims, err := jwt.DecodeJWTClaims(base64UrlEncodedClaims)
	assert.NoError(t, err)
	assert.Equal(t, claims.Issuer, decodedClaims.Issuer)
	assert.Equal(t, claims.Misc["c_nonce"], decodedClaims.Misc["c_nonce"])
}
