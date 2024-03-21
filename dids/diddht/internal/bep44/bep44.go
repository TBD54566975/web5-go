package bep44

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Message Represents a BEP44 message, which is used for storing and retrieving data in the Mainline DHT
// network.
//
// A BEP44 message is used primarily in the context of the DID DHT method for publishing and
// resolving DID documents in the DHT network. This type encapsulates the data structure required
// for such operations in accordance with BEP44.
//
// https://www.bittorrent.org/beps/bep_0044.html
type Message struct {

	// The public key bytes of the Identity Key, which serves as the identifier in the DHT network for
	// the corresponding BEP44 message.
	//
	k []byte

	// The sequence number of the message, used to ensure the latest version of the data is retrieved
	// and updated. It's a monotonically increasing number.
	Seq int64

	// The signature of the message, ensuring the authenticity and integrity of the data. It's
	// computed over the bencoded sequence number and value.
	sig []byte

	// The actual data being stored or retrieved from the DHT network, typically encoded in a format
	// suitable for DNS packet representation of a DID Document.
	V []byte
}

// Signer is a function that signs a given payload and returns the signature.
type Signer func(payload []byte) ([]byte, error)

// NewMessage bencodes the payload, signes it with the signer and creates a new BEP44 message with the given sequence number, public key.
func NewMessage(dnsPayload []byte, seq int64, publicKeyBytes []byte, signer Signer) (*Message, error) {
	bencodedBytes, err := bencodeBepPayload(seq, dnsPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to bencode payload: %w", err)
	}

	// remove the 1st (d) and last (e) byte from the bencoded bytes to conform to the BEP44 spec
	// and sign the payload
	signedBytes, err := signer(bencodedBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	bep := &Message{
		k:   publicKeyBytes,
		Seq: seq,
		sig: signedBytes,
		V:   dnsPayload,
	}

	return bep, nil
}

// Marshal encodes the BEP44 message into a byte slice, conforming to the Pkarr relay specification.
func (msg *Message) Marshal() ([]byte, error) {
	// Construct the body of the request according to the Pkarr relay specification.
	body := make([]byte, 0, len(msg.V)+72)
	body = append(body, msg.sig...)

	// Convert the sequence number to a big-endian byte array.
	seq := uint64(msg.Seq)
	buf := make([]byte, 8) // uint64 is 8 bytes
	binary.BigEndian.PutUint64(buf, seq)
	body = append(body, buf...)
	body = append(body, msg.V...)

	return body, nil
}

// UnmarshalMessage decodes the given byte slice into a BEP44 message.
func UnmarshalMessage(data []byte, b *Message) error {
	if len(data) < 72 {
		return fmt.Errorf("pkarr response must be at least 72 bytes but got: %d", len(data))
	}

	if len(data) > 1072 {
		return fmt.Errorf("pkarr response is larger than 1072 bytes, got: %d", len(data))
	}

	b.sig = data[:64]
	b.Seq = int64(binary.BigEndian.Uint64(data[64:72]))
	b.V = data[72:]

	return nil
}

func bencodeBepPayload(seq int64, v []byte) ([]byte, error) {
	if len(v) == 0 {
		return nil, errors.New("v cannot be empty")
	}

	re := fmt.Sprintf("3:seqi%de1:v%d:%s", seq, len(v), v)
	if len(re) > 1000 {
		return nil, errors.New("bencoded payload is too large")
	}
	return []byte(re), nil
}
