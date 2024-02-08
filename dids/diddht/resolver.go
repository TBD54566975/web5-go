package diddht

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/tbd54566975/web5-go/dids/did"
	"github.com/tbd54566975/web5-go/dids/didcore"
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

	bep44Message := bep44Message{} //nolint:govet
	if err := DecodeBEP44Message(data, &bep44Message); err != nil {
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

// put Publishes a signed BEP44 message to a Pkarr relay server.
// https://github.com/Nuhvi/pkarr/blob/main/design/relays.md
// relay - The Pkarr relay server URL.
// bep44Message - The BEP44 message to be published, containing the signed DNS packet.
// Returns an error if the request fails.
func (r *Resolver) put(did *did.BearerDID, msg *bep44Message) error {

	// The identifier (key in the DHT) is the z-base-32 encoding of the Identity Key.
	identifier := did.ID

	// Concatenate the Pkarr relay URL with the identifier to form the full URL.
	pkarrUrl, err := url.JoinPath(r.relay, identifier)
	if err != nil {
		// TODO log err
		return err
	}

	// Construct the body of the request according to the Pkarr relay specification.
	body := make([]byte, 0, len(msg.v)+72)
	body = append(body, msg.sig...)
	var seqUint64 uint64 = uint64(msg.seq)

	// Convert the sequence number to a big-endian byte array.
	buf := make([]byte, 8) // uint64 is 8 bytes
	binary.BigEndian.PutUint64(buf, seqUint64)
	body = append(body, buf...)
	body = append(body, msg.v...)

	req, err := http.NewRequest(http.MethodPut, pkarrUrl, strings.NewReader(string(body)))
	if err != nil {
		// TODO log err
		return err
	}

	req.Header.Set("Content-Type", "application/octet-stream")

	// Transmit the Put request to the Pkarr relay and get the response.
	res, err := r.client.Do(req)
	if err != nil {
		// TODO log err
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		// TODO log err
		return fmt.Errorf("failed to put message: %s", res.Status)
	}

	// Return `true` if the DHT request was successful, otherwise return `false`.
	return nil
}
