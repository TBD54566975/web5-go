package pkarr

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/tbd54566975/web5-go/dids/diddht/internal/bep44"
)

// Client is a client for publishing and fetching BEP44 messages to and from a Pkarr relay server.
type Client struct {
	relay  string
	client *http.Client
}

// NewClient creates a new Pkarr relay client with the given relay URL and HTTP client.
func NewClient(relay string, client *http.Client) *Client {
	return &Client{
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
func (r *Client) Put(didID string, msg *bep44.Message) error {
	return r.PutWithContext(context.Background(), didID, msg)
}

// PutWithContext same as put but with context
func (r *Client) PutWithContext(ctx context.Context, didID string, msg *bep44.Message) error {

	// Concatenate the Pkarr relay URL with the identifier to form the full URL.
	pkarrURL, err := url.JoinPath(r.relay, didID)
	if err != nil {
		return err
	}

	// Serialize the BEP44 message to a byte slice.
	body, err := msg.Marshal()
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, pkarrURL, strings.NewReader(string(body)))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/octet-stream")

	// Transmit the Put request to the Pkarr relay and get the response.
	res, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("failed to put message: %s - %s", res.Status, string(resBody))
	}

	// Return `true` if the DHT request was successful, otherwise return `false`.
	return nil
}

// Fetch fetches a signed BEP44 message from a Pkarr relay server.
func (r *Client) Fetch(didID string) (*bep44.Message, error) {
	return r.FetchWithContext(context.Background(), didID)
}

// FetchWithContext fetches a signed BEP44 message from a Pkarr relay server.
func (r *Client) FetchWithContext(ctx context.Context, didID string) (*bep44.Message, error) {
	// Concatenate the Pkarr relay URL with the identifier to form the full URL.
	pkarrURL, err := url.JoinPath(r.relay, didID)
	if err != nil {
		// TODO log err
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pkarrURL, nil)
	if err != nil {
		return nil, err
	}

	// Transmit the Get request to the Pkarr relay and get the response.
	res, err := r.client.Do(req)
	if err != nil {
		// TODO log err
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		// TODO log err
		return nil, fmt.Errorf("failed to get message: %s", res.Status)
	}

	// Read the response body into a byte slice.
	body, err := io.ReadAll(res.Body)
	if err != nil {
		// TODO log err
		return nil, err
	}

	// Decode the response body into a BEP44 message.
	bep44Message := bep44.Message{}
	if err := bep44.UnmarshalMessage(body, &bep44Message); err != nil {
		// TODO log err
		return nil, err
	}

	// Return the BEP44 message.
	return &bep44Message, nil
}
