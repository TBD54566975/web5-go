package jwt_test

import (
	"encoding/json"
	"testing"

	"github.com/tbd54566975/web5-go/dids"
	"github.com/tbd54566975/web5-go/jwt"
)

func TestClaims_MarshalJSON(t *testing.T) {
	claims := jwt.Claims{
		Issuer: "issuer",
		Misc:   map[string]interface{}{"foo": "bar"},
	}

	b, err := json.Marshal(&claims)
	if err != nil {
		t.Fatal(err)
	}

	obj := make(map[string]interface{})
	if err := json.Unmarshal(b, &obj); err != nil {
		t.Fatal(err)
	}

	if obj["iss"] != "issuer" {
		t.Errorf("expected iss to be 'issuer', got %v", obj["iss"])
	}

	if obj["foo"] == nil {
		t.Errorf("expected foo to not be nil")
	}
}

func TestClaims_UnmarshalJSON(t *testing.T) {
	claims := jwt.Claims{
		Issuer: "issuer",
		Misc:   map[string]interface{}{"foo": "bar"},
	}

	b, err := json.Marshal(&claims)
	if err != nil {
		t.Fatal(err)
	}

	claimsAgane := jwt.Claims{}
	json.Unmarshal(b, &claimsAgane)

	if claimsAgane.Issuer != claims.Issuer {
		t.Errorf("expected claims issuer to be %v. got %v", claims.Issuer, claimsAgane.Issuer)
	}

	if claimsAgane.Misc["foo"] == nil {
		t.Errorf("expected private claim to be present")
	}

	if claimsAgane.Misc["foo"] != claims.Misc["foo"] {
		t.Errorf("expected private claim to be %v. got %v",
			claims.Misc["foo"], claimsAgane.Misc["foo"])
	}
}

func TestClaims_Sign(t *testing.T) {
	did, err := dids.NewDIDJWK()
	if err != nil {
		t.Fatal(err)
	}

	claims := jwt.Claims{
		Issuer: did.ID,
		Misc:   map[string]interface{}{"c_nonce": "abcd123"},
	}

	jwt, err := jwt.Sign(claims, did)
	if err != nil {
		t.Fatal(err)
	}

	if jwt == "" {
		t.Errorf("expected jwt to not be empty")
	}
}

func TestClaims_Verify(t *testing.T) {
	did, err := dids.NewDIDJWK()
	if err != nil {
		t.Fatal(err)
	}

	claims := jwt.Claims{
		Issuer: did.ID,
		Misc:   map[string]interface{}{"c_nonce": "abcd123"},
	}

	signedJwt, err := jwt.Sign(claims, did)
	if err != nil {
		t.Fatal(err)
	}

	if signedJwt == "" {
		t.Errorf("expected jwt to not be empty")
	}

	verified, err := jwt.Verify(signedJwt)
	if err != nil {
		t.Fatal(err)
	}

	if !verified {
		t.Errorf("expected jwt to be verified")
	}
}
