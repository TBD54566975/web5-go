package main

import (
	"context"

	"github.com/alecthomas/kong"
)

type CLI struct {
	DID struct {
		Resolve didResolveCMD `cmd:"" help:"Resolve a DID."`
		Create  didCreateCMD  `cmd:"" help:"Create a DID."`
	} `cmd:"" help:"Interface with DID's."`
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
