package diddht

import (
	"context"
	"net/http"

	"github.com/tbd54566975/web5-go/dids/did"
	"github.com/tbd54566975/web5-go/dids/didcore"
	"github.com/tbd54566975/web5-go/dids/diddht/internal/dns"
	"github.com/tbd54566975/web5-go/dids/diddht/internal/pkarr"
	"github.com/tv42/zbase32"
)

// Resolver is a client for resolving DIDs using the DHT network.
type Resolver struct {
	relay relay
}

// NewResolver creates a new Resolver instance with the given relay and HTTP client.
// TODO make this relay an option and use default relay if not provided
func NewResolver(relayURL string, client *http.Client) *Resolver {
	pkarrRelay := pkarr.NewPkarrRelay(relayURL, client)
	return &Resolver{
		relay: pkarrRelay,
	}
}

// Resolve resolves a DID using the DHT method
func (r *Resolver) Resolve(uri string) (didcore.ResolutionResult, error) {
	return r.ResolveWithContext(context.Background(), uri)
}

// Resolve resolves a DID using the DHT method
func (r *Resolver) ResolveWithContext(ctx context.Context, uri string) (didcore.ResolutionResult, error) {

	// 1. Parse URI and make sure it's a DHT method
	did, err := did.Parse(uri)
	if err != nil {
		// TODO log err
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	if did.Method != "dht" {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	// 2. ensure did ID is zbase32
	identifier, err := zbase32.DecodeString(did.ID)
	if err != nil {
		// TODO log err
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	if len(identifier) == 0 {
		// return nil, fmt.Errorf("no bytes decoded from zbase32 identifier %s", did.ID)
		// TODO log err
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	// 3. fetch from the relay
	bep44Message, err := r.relay.FetchWithContext(ctx, did.ID)
	if err != nil {
		// TODO log err
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	bep44MessagePayload, err := bep44Message.DecodePayload()
	if err != nil {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	document, err := dns.UnmarshalDIDDocument(uri, bep44MessagePayload)
	if err != nil {
		// TODO log err
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	return didcore.ResolutionResultWithDocument(*document), nil
}
