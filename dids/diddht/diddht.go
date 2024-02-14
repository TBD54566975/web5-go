package diddht

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/tbd54566975/web5-go/crypto"
	"github.com/tbd54566975/web5-go/crypto/dsa"
	"github.com/tbd54566975/web5-go/dids/did"
	"github.com/tbd54566975/web5-go/dids/didcore"
	"github.com/tbd54566975/web5-go/dids/diddht/internal/bep44"
	"github.com/tbd54566975/web5-go/dids/diddht/internal/pkarr"
	"github.com/tv42/zbase32"
)

// relay is the internal interface used to publish Pakrr messages to the DHT
type relay interface {
	Put(string, *bep44.Message) error
	PutWithContext(context.Context, string, *bep44.Message) error
}

var defaultRelay relay
var once sync.Once

// getDefaultRelay returns the default Pkarr relay client.
func getDefaultRelay() relay {
	once.Do(func() {
		defaultRelay = pkarr.NewPkarrRelay("", http.DefaultClient)
	})

	return defaultRelay
}

// Decoder is used to structure the DNS representation of a DID
type Decoder struct {
	rootRecord string
	records    map[string]string
}

func (rec *Decoder) DIDDocument(didURI string) (*didcore.Document, error) {
	if len(rec.rootRecord) == 0 {
		return nil, errors.New("no root record found")
	}
	relationshipMap, err := parseVerificationRelationships(rec.rootRecord)
	if err != nil {
		return nil, err
	}

	// Now we have a did in a dns record. yay
	document := &didcore.Document{
		ID: didURI,
	}

	// Now create the did document
	for name, data := range rec.records {
		switch {
		case strings.HasPrefix(name, "_k"):
			var vMethod didcore.VerificationMethod
			if err := UnmarshalVerificationMethod(data, &vMethod); err != nil {
				// TODO handle error
				continue
			}

			// TODO somehow we need to keep track of the order - verification method index should keep entryId order
			// extracting kN from _kN._did
			entryID := strings.Split(name, ".")[0][1:]
			relationships, ok := relationshipMap[entryID]

			if !ok {
				// no relationships
				continue
			}

			opts := []didcore.Purpose{}
			for _, r := range relationships {
				if o, ok := vmPurposeDNStoDID[r]; ok {
					opts = append(opts, didcore.Purpose(o))
				}
			}

			document.AddVerificationMethod(
				vMethod,
				didcore.Purposes(opts...),
			)
		case strings.HasPrefix(name, "_s"):
			var s didcore.Service
			if err := UnmarshalService(data, &s); err != nil {
				// TODO handle error
				continue
			}
			document.AddService(&s)
		case strings.HasPrefix(name, "_cnt"):
			// TODO add controller https://did-dht.com/#controller
			// optional field
			// comma-separated list of controller DID identifiers
			document.Controller = strings.Split(data, ",")
		case strings.HasPrefix(name, "_aka"):
			// TODO add aka https://did-dht.com/#also-known-as
			document.AlsoKnownAs = strings.Split(data, ",")
		default:
		}
	}

	return document, nil
}

// parseDNSDID takes the bytes of the DNS representation of a DID and creates an internal representation
// used to create a DID document
func parseDNSDID(data []byte) (*Decoder, error) {
	var p dnsmessage.Parser
	if _, err := p.Start(data); err != nil {
		return nil, err
	}

	didRecord := Decoder{
		records: make(map[string]string),
	}

	// need to skip questions to move the index to the right place to read answers
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}

	for {
		h, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}

		if h.Type != dnsmessage.TypeTXT {
			continue
		}

		value, err := p.TXTResource()
		if err != nil {
			// TODO check what kind of error and see if this should fail
			return nil, err
		}

		name := h.Name.String()
		fullTxtRecord := strings.Join(value.TXT, "")
		if strings.HasPrefix(name, "_did") {
			didRecord.rootRecord = fullTxtRecord
			continue
		}

		if _, ok := didRecord.records[h.Name.String()]; !ok {
			// TODO handle error
		}
		didRecord.records[h.Name.String()] = fullTxtRecord
	}

	return &didRecord, nil
}

// TODO on the diddhtrecord we should validate the minimum reqs for a valid did
func parseVerificationRelationships(rootRecord string) (map[string][]string, error) {
	rootRecordProps, err := parseTXTRecordData(rootRecord)
	if err != nil {
		return nil, err
	}
	// reverse the map to get the relationships
	relationshipMap := map[string][]string{}
	for k, values := range rootRecordProps {
		v := strings.Join(values, "")
		rel, ok := relationshipMap[v]
		if !ok {
			rel = []string{}
		}
		rel = append(rel, k)
		relationshipMap[v] = rel
	}

	return relationshipMap, nil
}

func parseTXTRecordData(data string) (map[string][]string, error) {
	result := map[string][]string{}
	fields := strings.Split(data, ";")
	if len(fields) == 0 {
		return nil, errors.New("no fields found")
	}
	for _, field := range fields {
		kv := strings.Split(field, "=")
		if len(kv) != 2 {
			return nil, fmt.Errorf("malformed field %s", field)
		}
		k, v := kv[0], strings.Split(kv[1], ",")
		current, ok := result[k]
		if ok {
			v = append(current, v...)
		}
		result[k] = v
	}

	return result, nil
}

type DHTDidOptions struct {
	algorithmID         string
	keyManager          crypto.KeyManager
	services            []*didcore.Service
	verificationMethods []didcore.VerificationMethod
	purposes            map[string][]didcore.Purpose
	relay               relay
}

type DHTDidOption func(o *DHTDidOptions)

func WithServices(services ...*didcore.Service) DHTDidOption {
	return func(o *DHTDidOptions) {
		o.services = append(o.services, services...)
	}
}

func WithVerificationMethod(method didcore.VerificationMethod, purposes []didcore.Purpose) DHTDidOption {
	return func(o *DHTDidOptions) {
		o.verificationMethods = append(o.verificationMethods, method)
		for _, p := range purposes {
			if _, ok := o.purposes[method.ID]; !ok {
				o.purposes[method.ID] = []didcore.Purpose{}
			}
			o.purposes[method.ID] = append(o.purposes[method.ID], p)
		}
	}
}

func WithKeyManager(k crypto.KeyManager) DHTDidOption {
	return func(o *DHTDidOptions) {
		o.keyManager = k
	}
}

func WithRelay(relay relay) DHTDidOption {
	return func(o *DHTDidOptions) {
		o.relay = relay
	}
}

// Create creates a new `did:dht` DID and publishes it to the DHT network via a Pkarr relay.
//
// If no relay is passed in the options, Create uses a default Pkarr relay.
// Spec: https://did-dht.com/#create
func Create(opts ...DHTDidOption) (*did.BearerDID, error) {
	return CreateWithContext(context.Background(), opts...)
}

func CreateWithContext(ctx context.Context, opts ...DHTDidOption) (*did.BearerDID, error) {

	// 0. Set default options
	o := DHTDidOptions{
		algorithmID:         dsa.AlgorithmIDED25519,
		verificationMethods: []didcore.VerificationMethod{},
		services:            []*didcore.Service{},
		keyManager:          crypto.NewLocalKeyManager(),
		relay:               getDefaultRelay(),
		purposes:            map[string][]didcore.Purpose{},
	}

	for _, opt := range opts {
		opt(&o)
	}

	// 1. Generate an Ed25519 keypair
	keyMgr := o.keyManager

	keyID, err := keyMgr.GeneratePrivateKey(o.algorithmID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	publicKey, err := keyMgr.GetPublicKey(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	publicKeyBytes, err := dsa.PublicKeyToBytes(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key to bytes: %w", err)
	}

	// 2. Encode public key in zbase32
	zbase32Encoded := zbase32.EncodeToString(publicKeyBytes)

	// 3. Create a DID with the zbase32 encoded public key - did:dht:<zbase32 encoded public key>
	bdid := &did.BearerDID{
		DID: did.DID{
			Method: "dht",
			URI:    "did:dht:" + zbase32Encoded,
			ID:     zbase32Encoded,
		},
	}

	document := didcore.Document{
		Context:            "https://www.w3.org/ns/did/v1",
		ID:                 bdid.URI,
		Service:            []*didcore.Service{},
		VerificationMethod: []didcore.VerificationMethod{},
	}

	// 4. Construct a conformant JSON representation of a DID Document.
	for _, vm := range o.verificationMethods {
		purposes, ok := o.purposes[vm.ID]
		if !ok {
			purposes = []didcore.Purpose{}
		}
		document.AddVerificationMethod(vm, didcore.Purposes(purposes...))
	}

	for _, s := range o.services {
		document.AddService(s)
	}

	// 5. Map the output DID Document to a DNS packet
	var msg dnsmessage.Message
	if err := MarshalDIDDocument(&document, &msg); err != nil {
		return nil, fmt.Errorf("failed to marshal did document to dns packet: %w", err)
	}

	// 6. Construct a signed BEP44 put message with the v value as a bencoded DNS packet from the prior step.
	msgBytes, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack dns message: %w", err)
	}
	seq := time.Now().Unix() / 1000

	signer := func(payload []byte) ([]byte, error) {
		return keyMgr.Sign(keyID, payload)
	}

	bep44Msg, err := bep44.NewSignedBEP44Message(msgBytes, seq, publicKeyBytes, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create signed bep44 message: %w", err)
	}

	if o.relay == nil {
		return nil, fmt.Errorf("no relay provided")
	}

	// 7. Submit the result of to the DHT via a Pkarr relay, or a Gateway, with the identifier created in step 1.
	if err := o.relay.PutWithContext(ctx, bdid.ID, bep44Msg); err != nil {
		return nil, fmt.Errorf("failed to punlish bep44 message to relay: %w", err)
	}

	bdid.Document = document
	return bdid, nil
}
