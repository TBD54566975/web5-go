package main

import (
	"encoding/json"
	"fmt"

	"github.com/tbd54566975/web5-go/dids/didjwk"
	"github.com/tbd54566975/web5-go/dids/didweb"
)

type didCreateCmd struct {
	JWK didCreateJWKCmd `cmd:"" help:"Create did:jwk's."`
	Web didCreateWebCmd `cmd:"" help:"Create did:web's."`
}

type didCreateJWKCmd struct{}

func (c *didCreateJWKCmd) Run() error {
	did, err := didjwk.Create()
	if err != nil {
		return err
	}

	portableDID, err := did.ToPortableDID()
	if err != nil {
		return err
	}

	jsonDID, err := json.MarshalIndent(portableDID, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(jsonDID))

	return nil
}

type didCreateWebCmd struct {
	Domain string `arg:"" help:"The domain name for the DID." required:""`
}

func (c *didCreateWebCmd) Run() error {
	did, err := didweb.Create(c.Domain)
	if err != nil {
		return err
	}

	portableDID, err := did.ToPortableDID()
	if err != nil {
		return err
	}

	jsonDID, err := json.MarshalIndent(portableDID, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(jsonDID))

	return nil
}
