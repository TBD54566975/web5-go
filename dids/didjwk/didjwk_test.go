package didjwk_test

import (
	"fmt"
	"testing"

	"github.com/alecthomas/assert/v2"
	web5go "github.com/tbd54566975/web5-go"
	"github.com/tbd54566975/web5-go/dids/didcore"
	"github.com/tbd54566975/web5-go/dids/didjwk"
	"github.com/tbd54566975/web5-go/jwk"
)

func TestCreate(t *testing.T) {
	did, err := didjwk.Create()
	assert.NoError(t, err)

	assert.Equal(t, "jwk", did.Method)
	assert.True(t, did.Fragment == "", "expected fragment to be empty")
	assert.True(t, did.Path == "", "expected path to be empty")
	assert.True(t, did.Query == "", "expected query to be empty")
	assert.True(t, did.ID != "", "expected id to be non-empty")
	assert.Equal(t, "did:jwk:"+did.ID, did.URI)
}

func TestResolveDIDJWK(t *testing.T) {
	resolver := &didjwk.Resolver{}
	result, err := resolver.Resolve("did:jwk:eyJraWQiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1icHJpbnQ6c2hhLTI1NjpGZk1iek9qTW1RNGVmVDZrdndUSUpqZWxUcWpsMHhqRUlXUTJxb2JzUk1NIiwia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsImFsZyI6IkVkRFNBIiwieCI6IkFOUmpIX3p4Y0tCeHNqUlBVdHpSYnA3RlNWTEtKWFE5QVBYOU1QMWo3azQifQ")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(result.Document.VerificationMethod))

	vm := result.Document.VerificationMethod[0]
	assert.True(t, vm != didcore.VerificationMethod{}, "expected verification method to be non-empty")
	assert.NotEqual[jwk.JWK](t, *vm.PublicKeyJwk, jwk.JWK{}, "expected publicKeyJwk to be non-empty")

	assert.Equal(t, 1, len(result.Document.Authentication))
	assert.Equal(t, 1, len(result.Document.AssertionMethod))
}

func TestVector_Resolve(t *testing.T) {
	testVectors, err :=
		web5go.ReadTestVector[string, didcore.ResolutionResult]("../../web5-spec/test-vectors/did_jwk/resolve.json")
	assert.NoError(t, err)
	fmt.Println("Running test vectors: ", testVectors.Description)

	resolver := &didjwk.Resolver{}

	for _, vector := range testVectors.Vectors {
		t.Run(vector.Description, func(t *testing.T) {
			fmt.Println("Running test vector: ", vector.Description)
			result, err := resolver.Resolve(vector.Input)

			if vector.Errors {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, vector.Output, result)
			}
		})
	}
}
