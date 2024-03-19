package main

import (
	"encoding/json"
	"fmt"

	"github.com/tbd54566975/web5-go/jwt"
)

type jwtVerifyCMD struct {
	JWT      string `arg:"" help:"The base64 encoded JWT"`
	Claims   bool   `help:"Only print the JWT Claims." default:"false"`
	NoIndent bool   `help:"Print the decoded VC-JWT without indentation." default:"false"`
}

func (c *jwtVerifyCMD) Run() error {
	decoded, err := jwt.Verify(c.JWT)
	if err != nil {
		return err
	}

	var partToPrint any
	if c.Claims {
		partToPrint = decoded.Claims
	} else {
		partToPrint = decoded
	}

	var bytes []byte
	if c.NoIndent {
		bytes, err = json.Marshal(partToPrint)
	} else {
		bytes, err = json.MarshalIndent(partToPrint, "", "  ")
	}
	if err != nil {
		return err
	}

	fmt.Println(string(bytes))

	return nil
}
