package main

import (
	"encoding/json"
	"fmt"

	"github.com/tbd54566975/web5-go/dids/did"
	"github.com/tbd54566975/web5-go/jwt"
)

type jwtSignCMD struct {
	Claims      string `arg:"" help:"The JWT Claims. Value is a JSON string."`
	PortableDID string `arg:"" help:"The Portable DID to sign with. Value is a JSON string."`
	Purpose     string `help:"Used to specify which key from the given DID Document should be used."`
	Type        string `help:"Used to set the JWS Header 'typ' property"`
}

func (c *jwtSignCMD) Run() error {
	var claims jwt.Claims
	err := json.Unmarshal([]byte(c.Claims), &claims)
	if err != nil {
		return fmt.Errorf("%s: %w", "invalid credential", err)
	}

	var portableDID did.PortableDID
	err = json.Unmarshal([]byte(c.PortableDID), &portableDID)
	if err != nil {
		return fmt.Errorf("%s: %w", "invalid portable DID", err)
	}

	bearerDID, err := did.FromPortableDID(portableDID)
	if err != nil {
		return err
	}

	opts := []jwt.SignOpt{}
	if c.Purpose != "" {
		opts = append(opts, jwt.Purpose(c.Purpose))
	}
	if c.Type != "" {
		opts = append(opts, jwt.Type(c.Type))
	}

	signed, err := jwt.Sign(claims, bearerDID, opts...)
	if err != nil {
		return err
	}

	fmt.Println(signed)

	return nil
}
