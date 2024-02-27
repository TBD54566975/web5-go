package main

import (
	"context"

	"github.com/alecthomas/kong"
)

type CLI struct {
	DID struct {
		Resolve didResolveCmd `cmd:"" help:"Resolve a DID."`
		Create  didCreateCmd  `cmd:"" help:"Create a DID."`
	} `cmd:"" help:"Interface with DID's."`
}

var cli CLI

func main() {
	kctx := kong.Parse(&cli,
		kong.Description("Web5 - A decentralized web platform that puts you in control of your data and identity."),
	)

	ctx := context.Background()
	kctx.BindTo(ctx, (*context.Context)(nil))
	err := kctx.Run(ctx)
	kctx.FatalIfErrorf(err)
}
