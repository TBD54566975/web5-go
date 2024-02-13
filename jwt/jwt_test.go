package jwt_test

import (
	"encoding/json"
	"fmt"
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

	assert.Equal(t, "issuer", obj["iss"])
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

	signedJWT, err := jwt.Sign(claims, did)
	assert.NoError(t, err)

	assert.False(t, signedJWT == "", "expected jwt to not be empty")

	decoded, err := jwt.Verify(signedJWT)
	assert.NoError(t, err)
	assert.NotEqual(t, decoded, jwt.Decoded{}, "expected decoded to not be empty")
}

func TestVerify_BadClaims(t *testing.T) {
	okHeader, err := jws.Header{ALG: "ES256K", KID: "did:web:abc#key-1"}.Encode()
	assert.NoError(t, err)

	input := fmt.Sprintf("%s.%s.%s", okHeader, "hehe", "hehe")

	decoded, err := jwt.Verify(input)
	assert.Error(t, err)
	assert.Equal(t, jwt.Decoded{}, decoded)
}

func Test_Decode_Empty(t *testing.T) {
	decoded, err := jwt.Decode("")
	assert.Error(t, err)
	assert.Equal(t, jwt.Decoded{}, decoded)
}
