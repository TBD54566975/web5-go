package diddht

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/tbd54566975/web5-go/dids/diddht/bencode"
)

// Represents a BEP44 message, which is used for storing and retrieving data in the Mainline DHT
// network.
//
// A BEP44 message is used primarily in the context of the DID DHT method for publishing and
// resolving DID documents in the DHT network. This type encapsulates the data structure required
// for such operations in accordance with BEP44.
//
// https://www.bittorrent.org/beps/bep_0044.html
type bep44Message struct {

	// The public key bytes of the Identity Key, which serves as the identifier in the DHT network for
	// the corresponding BEP44 message.
	//
	k []byte

	// The sequence number of the message, used to ensure the latest version of the data is retrieved
	// and updated. It's a monotonically increasing number.
	seq int64

	// The signature of the message, ensuring the authenticity and integrity of the data. It's
	// computed over the bencoded sequence number and value.
	sig []byte

	// The actual data being stored or retrieved from the DHT network, typically encoded in a format
	// suitable for DNS packet representation of a DID Document.
	v []byte
}

type signer func(payload []byte) ([]byte, error)

// newSignedBEP44Message creates a new signed BEP44 message with the given DNS payload.
func newSignedBEP44Message(dnsPayload []byte, seq int64, publicKeyBytes []byte, signer signer) (*bep44Message, error) {
	bencoded := map[string]any{
		"seq": seq,
		"v":   dnsPayload,
	}

	bencodedBytes, err := bencode.Marshal(bencoded)
	if err != nil {
		return nil, fmt.Errorf("failed to bencode: %w", err)
	}

	signedBytes, err := signer(bencodedBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	bep := &bep44Message{
		k:   publicKeyBytes,
		seq: seq,
		sig: signedBytes,
		v:   bencodedBytes,
	}

	return bep, nil
}

func (b *bep44Message) DecodePayload() ([]byte, error) {
	bdecoded := map[string]any{}
	if err := bencode.Unmarshal(b.v, &bdecoded); err != nil {
		return nil, fmt.Errorf("failed to decode bencoded payload: %w", err)
	}

	v, ok := bdecoded["v"].(string)
	if !ok {
		return nil, errors.New("failed to decode v value")
	}
	return []byte(v), nil
}

// DecodeBEP44Message decodes the given byte slice into a BEP44 message.
func DecodeBEP44Message(data []byte, b *bep44Message) error {
	if len(data) < 72 {
		return fmt.Errorf("pkarr response must be at least 72 bytes but got: %d", len(data))
	}

	if len(data) > 1072 {
		return fmt.Errorf("pkarr response is larger than 1072 bytes, got: %d", len(data))
	}

	b.sig = data[:64]
	b.seq = int64(binary.BigEndian.Uint64(data[64:72]))
	b.v = data[72:]

	return nil
}
