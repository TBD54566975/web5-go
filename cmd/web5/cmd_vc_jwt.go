package main

import (
	"encoding/json"
	"fmt"

	"github.com/tbd54566975/web5-go/vc"
)

type vcJWTCMD struct {
	Verify vcJWTVerifyCMD `cmd:"" help:"Verify a VC-JWT."`
	Decode vcJWTDecodeCMD `cmd:"" help:"Decode a VC-JWT."`
}

type vcJWTVerifyCMD struct {
	JWT string `arg:"" help:"The VC-JWT"`
}

func (c *vcJWTVerifyCMD) Run() error {
	decoded, err := vc.Verify[vc.Claims](c.JWT)
	if err != nil {
		return err
	}

	jsonVC, err := json.MarshalIndent(decoded.VC, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(jsonVC))

	return nil
}

type vcJWTDecodeCMD struct {
	JWT string `arg:"" help:"The VC-JWT"`
}

func (c *vcJWTDecodeCMD) Run() error {
	decoded, err := vc.Decode[vc.Claims](c.JWT)
	if err != nil {
		return err
	}

	jsonVC, err := json.MarshalIndent(decoded.VC, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(jsonVC))

	return nil
}
