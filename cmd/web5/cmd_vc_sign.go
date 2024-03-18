package main

import (
	"encoding/json"
	"fmt"

	"github.com/tbd54566975/web5-go/dids/did"
	"github.com/tbd54566975/web5-go/vc"
)

type vcSignCMD struct {
	VC          string `arg:"" help:"The VC to sign. Value is a JSON string."`
	PortableDID string `arg:"" help:"The Portable DID to sign with. Value is a JSON string."`
}

func (c *vcSignCMD) Run() error {
	var credential vc.DataModel[vc.Claims]
	err := json.Unmarshal([]byte(c.VC), &credential)
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

	// TODO sign opts
	signed, err := credential.Sign(bearerDID)
	if err != nil {
		return err
	}

	fmt.Println(signed)

	return nil
}
