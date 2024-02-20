package vc_test

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/dids/didjwk"
	"github.com/tbd54566975/web5-go/vc"
)

func TestSomething(t *testing.T) {
	type YoloClaims struct {
		Hello string `json:"hello"`
	}

	claims := YoloClaims{Hello: "world"}
	cred := vc.Create(claims)

	bearerDID, err := didjwk.Create()
	if err != nil {
		assert.NoError(t, err)
	}

	cred.SignJWT(bearerDID)
}
