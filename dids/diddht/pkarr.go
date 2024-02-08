package diddht

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

var defaultRelay *pkarrRelay
var once sync.Once

func getDefaultRelay() *pkarrRelay {
	once.Do(func() {
		defaultRelay = NewPkarrRelay("", http.DefaultClient)
	})

	return defaultRelay
}

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

// put Publishes a signed BEP44 message to a Pkarr relay server.
// https://github.com/Nuhvi/pkarr/blob/main/design/relays.md
//
// didID - The DID identifier, used as the key in the DHT; it is the z-base-32 encoding of the Identity Key.
// bep44Message - The BEP44 message to be published, containing the signed DNS packet.
//
// Returns an error if the request fails.
func (r *pkarrRelay) put(didID string, msg *bep44Message) error {
	return r.putWithContext(context.Background(), didID, msg)
}

// putWithContext same as put but with context
func (r *pkarrRelay) putWithContext(ctx context.Context, didID string, msg *bep44Message) error {

	// Concatenate the Pkarr relay URL with the identifier to form the full URL.
	pkarrUrl, err := url.JoinPath(r.relay, didID)
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
