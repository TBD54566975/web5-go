package main

import (
	"context"

	"github.com/alecthomas/kong"
)

// CLI is the main command line interface for the web5 CLI.
// more information about this struct can be found in the [kong documentation]
//
// [kong documentation]: https://github.com/alecthomas/kong
type CLI struct {
	JWT struct {
		Sign jwtSignCMD `cmd:"" help:"Sign a JWT."`
		// todo decode and verify
	} `cmd:"" help:"Interface with JWT's."`
	DID struct {
		Resolve didResolveCMD `cmd:"" help:"Resolve a DID."`
		Create  didCreateCMD  `cmd:"" help:"Create a DID."`
	} `cmd:"" help:"Interface with DID's."`
	VC struct {
		Create vcCreateCMD `cmd:"" help:"Create a VC."`
		Sign   vcSignCMD   `cmd:"" help:"Sign a VC."`
		JWT    vcJWTCMD    `cmd:"" help:"Tooling for VC-JWT's"`
	} `cmd:"" help:"Interface with VC's."`
}

func main() {
	kctx := kong.Parse(&CLI{},
		kong.Description("Web5 - A decentralized web platform that puts you in control of your data and identity."),
	)

	ctx := context.Background()
	kctx.BindTo(ctx, (*context.Context)(nil))
	err := kctx.Run(ctx)
	kctx.FatalIfErrorf(err)
}
