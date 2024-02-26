package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/tbd54566975/web5-go/dids"
)

type didResolve struct {
	URI string `arg:"" name:"uri" help:"The URI to resolve."`
}

func (c *didResolve) Run(_ context.Context) error {
	fmt.Println(c.URI)

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

type didCmd struct {
	Resolve didResolve `cmd:"" help:"Resolve a DID."`
}
