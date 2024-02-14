package diddht

import (
	"fmt"
	"io"
	"net/http"

	"github.com/tbd54566975/web5-go/dids/did"
	"github.com/tbd54566975/web5-go/dids/didcore"
	"github.com/tbd54566975/web5-go/dids/diddht/internal/bep44"
	"github.com/tv42/zbase32"
)

// Resolver is a client for resolving DIDs using the DHT network.
type Resolver struct {
	relay  string
	client *http.Client
}

// NewResolver creates a new Resolver instance with the given relay and HTTP client.
func NewResolver(relay string, client *http.Client) *Resolver {
	return &Resolver{
		relay:  relay,
		client: client,
	}
}

// Resolve resolves a DID using the DHT method
func (r *Resolver) Resolve(uri string) (didcore.ResolutionResult, error) {

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

	// 3. fetch from DHT
	res, err := r.client.Get(fmt.Sprintf("%s/%s", r.relay, did.ID)) //nolint:noctx
	if err != nil {
		// TODO log err
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		// TODO log err
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	bep44Message := bep44.Message{}
	if err := bep44.DecodeBEP44Message(data, &bep44Message); err != nil {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	bep44MessagePayload, err := bep44Message.DecodePayload()
	if err != nil {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	didRecord, err := parseDNSDID(bep44MessagePayload)
	if err != nil {
		// TODO log err
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	document, err := didRecord.DIDDocument(uri)
	if err != nil {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}
	return didcore.ResolutionResultWithDocument(*document), nil
}
