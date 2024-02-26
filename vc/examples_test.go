package vc_test

import (
	"fmt"

	"github.com/tbd54566975/web5-go/dids/didjwk"
	"github.com/tbd54566975/web5-go/vc"
)

func Example() {
	issuer, err := didjwk.Create()
	if err != nil {
		panic(err)
	}

	claims := vc.Claims{"name": "Randy McRando"}
	cred := vc.Create(claims)

	vcJWT, err := cred.Sign(issuer)
	if err != nil {
		panic(err)
	}

	decoded, err := vc.Verify[vc.Claims](vcJWT)
	if err != nil {
		panic(err)
	}

	fmt.Println(decoded.VC.CredentialSubject["name"])
	// Output: Randy McRando
}

type KnownCustomerClaims struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (c KnownCustomerClaims) GetID() string {
	return c.ID
}

func (c KnownCustomerClaims) SetID(id string) {
	c.ID = id
}

func Example_stronglyTyped() {
	issuer, err := didjwk.Create()
	if err != nil {
		panic(err)
	}

	subject, err := didjwk.Create()
	if err != nil {
		panic(err)
	}

	claims := KnownCustomerClaims{ID: subject.URI, Name: "Randy McRando"}
	cred := vc.Create(&claims)

	vcJWT, err := cred.Sign(issuer)
	if err != nil {
		panic(err)
	}

	decoded, err := vc.Verify[KnownCustomerClaims](vcJWT)
	if err != nil {
		panic(err)
	}

	fmt.Println(decoded.VC.CredentialSubject.Name)
	// Output: Randy McRando
}

func Example_mixed() {
	issuer, err := didjwk.Create()
	if err != nil {
		panic(err)
	}

	subject, err := didjwk.Create()
	if err != nil {
		panic(err)
	}

	claims := KnownCustomerClaims{ID: subject.URI, Name: "Randy McRando"}
	cred := vc.Create(&claims)

	vcJWT, err := cred.Sign(issuer)
	if err != nil {
		panic(err)
	}

	decoded, err := vc.Verify[vc.Claims](vcJWT)
	if err != nil {
		panic(err)
	}

	fmt.Println(decoded.VC.CredentialSubject["name"])
	// Output: Randy McRando
}
