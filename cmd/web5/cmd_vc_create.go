package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tbd54566975/web5-go/dids/did"
	"github.com/tbd54566975/web5-go/vc"
)

type vcCreateCMD struct {
	CredentialSubjectID string    `arg:"" help:"The Credential Subject's ID"`
	Claims              string    `help:"Add additional credentialSubject claims (JSON string). ex: '{\"name\": \"John Doe\"}'." default:"{}"`
	Contexts            []string  `help:"Add additional @context's to the default [\"https://www.w3.org/2018/credentials/v1\"]."`
	Types               []string  `help:"Add additional type's to the default [\"VerifiableCredential\"]."`
	ID                  string    `help:"Override the default ID of format urn:vc:uuid:<uuid>."`
	IssuanceDate        time.Time `help:"Override the default issuanceDate of time.Now()."`
	ExpirationDate      time.Time `help:"Override the default expirationDate of nil."`
	Sign                bool      `help:"Sign the VC with the provided --portable-did." default:"false"`
	PortableDID         string    `help:"Portable DID used with --sign. Value is a JSON string."`
	NoIndent            bool      `help:"Print the VC without indentation." default:"false"`
}

func (c *vcCreateCMD) Run() error {
	opts := []vc.CreateOption{}
	if len(c.Contexts) > 0 {
		opts = append(opts, vc.Contexts(c.Contexts...))
	}
	if len(c.Types) > 0 {
		opts = append(opts, vc.Types(c.Types...))
	}
	if c.ID != "" {
		opts = append(opts, vc.ID(c.ID))
	}
	if (c.IssuanceDate != time.Time{}) {
		opts = append(opts, vc.IssuanceDate(c.IssuanceDate))
	}
	if (c.ExpirationDate != time.Time{}) {
		opts = append(opts, vc.ExpirationDate(c.ExpirationDate))
	}

	var claims vc.Claims
	err := json.Unmarshal([]byte(c.Claims), &claims)
	if err != nil {
		return fmt.Errorf("%s: %w", "invalid claims", err)
	}

	claims["id"] = c.CredentialSubjectID

	credential := vc.Create(claims, opts...)

	if c.Sign {
		if c.PortableDID == "" {
			return errors.New("--portable-did must be provided with --sign")
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

	var jsonVC []byte
	if c.NoIndent {
		jsonVC, err = json.Marshal(credential)
	} else {
		jsonVC, err = json.MarshalIndent(credential, "", "  ")
	}
	if err != nil {
		return err
	}

	fmt.Println(string(jsonVC))

	return nil
}
