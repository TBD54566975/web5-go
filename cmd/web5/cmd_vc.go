package main

import (
	"encoding/json"
	"fmt"
	"time"

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

	jsonDID, err := json.MarshalIndent(credential, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(jsonDID))

	return nil
}
