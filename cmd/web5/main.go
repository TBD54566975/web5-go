package main

import (
	"context"

	"github.com/alecthomas/kong"
)

var cli struct {
	DID    didCmd    `cmd:"" help:"Interface with DID's."`
	DIDJWK didJWKCmd `cmd:"" name:"did:jwk" help:"Manage did:jwk's."`
	DIDWeb didWebCmd `cmd:"" name:"did:web" help:"Manage did:web's."`
}

func main() {
	kctx := kong.Parse(&cli,
		kong.Description("Web5 - A decentralized web platform that puts you in control of your data and identity."),
	)

	ctx := context.Background()
	kctx.BindTo(ctx, (*context.Context)(nil))
	err := kctx.Run(ctx)
	kctx.FatalIfErrorf(err)
}
