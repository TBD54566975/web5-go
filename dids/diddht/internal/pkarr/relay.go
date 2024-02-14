package pkarr

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/tbd54566975/web5-go/dids/diddht/internal/bep44"
)

type pkarrRelay struct {
	relay  string
	client *http.Client
}

func NewPkarrRelay(relay string, client *http.Client) *pkarrRelay {
	return &pkarrRelay{
		relay:  relay,
		client: client,
	}
}

// Put Publishes a signed BEP44 message to a Pkarr relay server.
// https://github.com/Nuhvi/pkarr/blob/main/design/relays.md
//
// didID - The DID identifier, used as the key in the DHT; it is the z-base-32 encoding of the Identity Key.
// bep44Message - The BEP44 message to be published, containing the signed DNS packet.
//
// Returns an error if the request fails.
func (r *pkarrRelay) Put(didID string, msg *bep44.Message) error {
	return r.PutWithContext(context.Background(), didID, msg)
}

// PutWithContext same as put but with context
func (r *pkarrRelay) PutWithContext(ctx context.Context, didID string, msg *bep44.Message) error {

	// Concatenate the Pkarr relay URL with the identifier to form the full URL.
	pkarrUrl, err := url.JoinPath(r.relay, didID)
	if err != nil {
		// TODO log err
		return err
	}

	// Serialize the BEP44 message to a byte slice.
	body, _ := msg.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, pkarrUrl, strings.NewReader(string(body)))
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
