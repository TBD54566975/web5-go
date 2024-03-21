package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/tbd54566975/web5-go/dids/did"
	"github.com/tbd54566975/web5-go/dids/diddht"
	"github.com/tbd54566975/web5-go/dids/didjwk"
	"github.com/tbd54566975/web5-go/dids/didweb"
)

type didCreateCMD struct {
	JWK didCreateJWKCMD `cmd:"" help:"Create a did:jwk."`
	Web didCreateWebCMD `cmd:"" help:"Create a did:web."`
	DHT didCreateDHTCMD `cmd:"" help:"Create a did:dht."`
}

type didCreateJWKCMD struct {
	NoIndent bool `help:"Print the portable DID without indentation." default:"false"`
}

func (c *didCreateJWKCMD) Run() error {
	did, err := didjwk.Create()
	if err != nil {
		return err
	}

	return printDID(did, c.NoIndent)
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

	return printDID(did, c.NoIndent)
}

type didCreateDHTCMD struct {
	NoIndent bool `help:"Print the portable DID without indentation." default:"false"`
}

func (c *didCreateDHTCMD) Run() error {
	did, err := diddht.CreateWithContext(context.Background())
	if err != nil {
		return err
	}

	return printDID(did, c.NoIndent)
}

func printDID(d did.BearerDID, noIndent bool) error {
	portableDID, err := d.ToPortableDID()
	if err != nil {
		return err
	}

	var jsonDID []byte
	if noIndent {
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
