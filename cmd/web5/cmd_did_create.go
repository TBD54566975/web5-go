package main

import (
	"encoding/json"
	"fmt"

	"github.com/tbd54566975/web5-go/dids/didjwk"
	"github.com/tbd54566975/web5-go/dids/didweb"
)

type didCreateCMD struct {
	JWK didCreateJWKCMD `cmd:"" help:"Create a did:jwk."`
	Web didCreateWebCMD `cmd:"" help:"Create a did:web."`
}

type didCreateJWKCMD struct {
	NoIndent bool `help:"Print the portable DID without indentation." default:"false"`
}

func (c *didCreateJWKCMD) Run() error {
	did, err := didjwk.Create()
	if err != nil {
		return err
	}

	portableDID, err := did.ToPortableDID()
	if err != nil {
		return err
	}

	var jsonDID []byte
	if c.NoIndent {
		jsonDID, err = json.Marshal(portableDID)
	} else {
		jsonDID, err = json.MarshalIndent(portableDID, "", "  ")
	}

	if err != nil {
		return err
	}

	fmt.Println(string(jsonDID))

	return nil
}

type didCreateWebCMD struct {
	Domain   string `arg:"" help:"The domain name for the DID." required:""`
	NoIndent bool   `help:"Print the portable DID without indentation." default:"false"`
}

func (c *didCreateWebCMD) Run() error {
	did, err := didweb.Create(c.Domain)
	if err != nil {
		return err
	}

	portableDID, err := did.ToPortableDID()
	if err != nil {
		return err
	}

	var jsonDID []byte
	if c.NoIndent {
		jsonDID, err = json.Marshal(portableDID)
	} else {
		jsonDID, err = json.MarshalIndent(portableDID, "", "  ")
	}

	if err != nil {
		return err
	}

	fmt.Println(string(jsonDID))

	return nil
}
