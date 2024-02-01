package dids

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/jwk"
)

func TestNewDIDJWK(t *testing.T) {
	did, err := NewDIDJWK()
	assert.NoError(t, err)

	assert.Equal(t, did.Method, "jwk")
	assert.True(t, did.Fragment == "", "expected fragment to be empty")
	assert.True(t, did.Path == "", "expected path to be empty")
	assert.True(t, did.Query == "", "expected query to be empty")
	assert.True(t, did.ID != "", "expected id to be non-empty")
	assert.Equal(t, did.URI, "did:jwk:"+did.ID)
}

func TestResolveDIDJWK(t *testing.T) {
	result, err := ResolveDIDJWK("did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1icHJpbnQ6c2hhLTI1NjpGZk1iek9qTW1RNGVmVDZrdndUSUpqZWxUcWpsMHhqRUlXUTJxb2JzUk1NIiwia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImFsZyI6IkVkRFNBIiwieCI6IkFOUmpIX3p4Y0tCeHNqUlBVdHpSYnA3RlNWTEtKWFE5QVBYOU1QMWo3azQifQ")
	assert.NoError(t, err)
	assert.Equal(t, len(result.Document.VerificationMethod), 1)

	vm := result.Document.VerificationMethod[0]
	assert.True(t, vm != VerificationMethod{}, "expected verification method to be non-empty")
	assert.True(t, vm.PublicKeyJwk != (jwk.JWK{}), "expected publicKeyJwk to be non-empty")

	assert.Equal(t, len(result.Document.Authentication), 1)
	assert.Equal(t, len(result.Document.AssertionMethod), 1)
}
