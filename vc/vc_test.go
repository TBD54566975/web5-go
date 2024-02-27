package vc_test

import (
	"slices"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/dids/didjwk"
	"github.com/tbd54566975/web5-go/vc"
)

func TestCreate_Defaults(t *testing.T) {
	cred := vc.Create(vc.Claims{"id": "1234"})

	assert.Equal(t, 1, len(cred.Context))
	assert.Equal(t, vc.BaseContext, cred.Context[0])

	assert.Equal(t, 1, len(cred.Type))
	assert.Equal(t, vc.BaseType, cred.Type[0])

	assert.Contains(t, cred.ID, "urn:vc:uuid:")

	assert.NotZero(t, cred.IssuanceDate)

	_, err := time.Parse(time.RFC3339, cred.IssuanceDate)
	assert.NoError(t, err)

	assert.Equal(t, "1234", cred.CredentialSubject["id"])
}

func TestCreate_Options(t *testing.T) {
	claims := vc.Claims{"id": "1234"}
	issuanceDate := time.Now().UTC().Add(10 * time.Hour)
	expirationDate := issuanceDate.Add(30 * time.Hour)

	cred := vc.Create(
		claims,
		vc.ID("hehecustomid"),
		vc.Contexts("https://nocontextisbestcontext.gov"),
		vc.Types("StreetCredential"),
		vc.IssuanceDate(issuanceDate),
		vc.ExpirationDate(expirationDate),
	)

	assert.Equal(t, 2, len(cred.Context))
	assert.True(t, slices.Contains(cred.Context, "https://nocontextisbestcontext.gov"))
	assert.True(t, slices.Contains(cred.Context, vc.BaseContext))

	assert.Equal(t, 2, len(cred.Type))
	assert.True(t, slices.Contains(cred.Type, "StreetCredential"))
	assert.True(t, slices.Contains(cred.Type, vc.BaseType))

	assert.Equal(t, "hehecustomid", cred.ID)

	assert.NotZero(t, cred.ExpirationDate)
}

func TestSign(t *testing.T) {
	issuer, err := didjwk.Create()
	assert.NoError(t, err)

	subject, err := didjwk.Create()
	assert.NoError(t, err)

	claims := vc.Claims{"id": subject.URI, "name": "Randy McRando"}
	cred := vc.Create(claims)

	vcJWT, err := cred.Sign(issuer)
	assert.NoError(t, err)
	assert.NotZero(t, vcJWT)

	// TODO: make test more reliable by not depending on another function in this package (Moe - 2024-02-25)
	decoded, err := vc.Verify[vc.Claims](vcJWT)

	assert.NoError(t, err)
	assert.NotZero(t, decoded)
}
