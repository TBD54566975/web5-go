package vc_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/tbd54566975/web5-go/vc"
)

func TestSomething(t *testing.T) {
	type YoloClaims struct {
		Hello string `json:"hello"`
	}

	claims := YoloClaims{Hello: "world"}
	cred := vc.Create(claims)

	bytes, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf(string(bytes))
}
