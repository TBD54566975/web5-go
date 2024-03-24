package main

import (
	"encoding/json"
	"fmt"

	"github.com/tbd54566975/web5-go/vc"
)

type vcjwtDecodeCMD struct {
	JWT      string `arg:"" help:"The VC-JWT"`
	NoIndent bool   `help:"Print the decoded VC-JWT without indentation." default:"false"`
}

func (c *vcjwtDecodeCMD) Run() error {
	decoded, err := vc.Decode[vc.Claims](c.JWT)
	if err != nil {
		return err
	}

	var jsonVC []byte
	if c.NoIndent {
		jsonVC, err = json.Marshal(decoded.VC)
	} else {
		jsonVC, err = json.MarshalIndent(decoded.VC, "", "  ")
	}
	if err != nil {
		return err
	}

	fmt.Println(string(jsonVC))

	return nil
}
