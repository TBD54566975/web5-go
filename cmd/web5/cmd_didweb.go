package main

import (
	"encoding/json"
	"fmt"

	"github.com/tbd54566975/web5-go/dids/didweb"
)

type didWebCreate struct {
	Domain string `arg:"" help:"The domain name for the DID." required:""`
}

func (c *didWebCreate) Run() error {
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

type didWebCmd struct {
	Create didWebCreate `cmd:"" help:"Create a did:web."`
}
