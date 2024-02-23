package vc_test

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/dids/didjwk"
	"github.com/tbd54566975/web5-go/jwt"
	"github.com/tbd54566975/web5-go/vc"
)

func TestDecodeJWT(t *testing.T) {
	bearerDID, err := didjwk.Create()
	assert.NoError(t, err)

	cred := vc.Create(vc.Claims{"id": "1234"})
	vcJWT, err := cred.SignJWT(bearerDID)
	assert.NoError(t, err)

	decoded, err := vc.DecodeJWT[vc.Claims](vcJWT)
	assert.NoError(t, err)

	assert.NotEqual(t, jwt.Decoded{}, decoded.JWT)
	assert.NotEqual(t, vc.DataModel[vc.Claims]{}, decoded.VC)

}
