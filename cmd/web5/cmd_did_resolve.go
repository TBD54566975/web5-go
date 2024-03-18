package main

import (
	"encoding/json"
	"fmt"

	"github.com/tbd54566975/web5-go/dids"
)

type didResolveCMD struct {
	URI      string `arg:"" name:"uri" help:"The URI to resolve."`
	NoIndent bool   `help:"Print the DID Document without indentation." default:"false"`
}

func (c *didResolveCMD) Run() error {
	result, err := dids.Resolve(c.URI)
	if err != nil {
		return err
	}

	var jsonDIDDocument []byte
	if c.NoIndent {
		jsonDIDDocument, err = json.Marshal(result.Document)
	} else {
		jsonDIDDocument, err = json.MarshalIndent(result.Document, "", "  ")
	}
	if err != nil {
		return err
	}

	fmt.Println(string(jsonDIDDocument))

	return nil
}
