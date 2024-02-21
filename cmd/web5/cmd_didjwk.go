package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/tbd54566975/web5-go/dids/didjwk"
)

type didJWKCreate struct{}

func (c *didJWKCreate) Run(_ context.Context) error {
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

type didJWKCmd struct {
	Create didJWKCreate `cmd:"" help:"Create a did:jwk."`
}
