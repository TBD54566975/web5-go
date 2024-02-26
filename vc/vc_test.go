package vc_test

import (
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
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
