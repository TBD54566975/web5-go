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

type didCreateJWKCmd struct {
	AlgorithmID string `help:"The algorithm for generating the cryptographic keys."`
}

func (c *didCreateJWKCmd) Run() error {
	opts := []didjwk.CreateOption{}
	if c.AlgorithmID != "" {
		opts = append(opts, didjwk.AlgorithmID(c.AlgorithmID))
	}

	did, err := didjwk.Create(opts...)
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

// TODO move this into didcore/document.go if this is all right
// type Services []didcore.Service

// func (s *Services) UnmarshalJSON(data []byte) error {
// 	return json.Unmarshal(data, (*[]didcore.Service)(s))
// }

type didCreateWebCmd struct {
	Domain string `arg:"" help:"The domain name for the DID."`
	// Services    Services `help:"Add Services https://www.w3.org/TR/did-core/#services"`
	Services    []string `help:"Add Services https://www.w3.org/TR/did-core/#services"`
	AlsoKnownAs []string `help:"Add Also Known As https://www.w3.org/TR/did-core/#also-known-as"`
}

func (c *didCreateWebCmd) Run() error {
	opts := []didweb.CreateOption{}

	if len(c.AlsoKnownAs) > 0 {
		opts = append(opts, didweb.AlsoKnownAs(c.AlsoKnownAs...))
	}

	if len(c.AlsoKnownAs) > 0 {
		// todo
	}

	did, err := didweb.Create(c.Domain, opts...)
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
