package main

import (
	"encoding/json"
	"fmt"

	"github.com/tbd54566975/web5-go/dids"
)

type didResolveCMD struct {
	URI string `arg:"" name:"uri" help:"The URI to resolve."`
}

func (c *didResolveCMD) Run() error {
	result, err := dids.Resolve(c.URI)
	if err != nil {
		return err
	}

	jsonDID, err := json.MarshalIndent(result.Document, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(jsonDID))

	return nil
}
