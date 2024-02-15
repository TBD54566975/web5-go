package diddht

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/tbd54566975/web5-go/crypto"
	"github.com/tbd54566975/web5-go/crypto/dsa"
	"github.com/tbd54566975/web5-go/dids/did"
	"github.com/tbd54566975/web5-go/dids/didcore"
	"github.com/tbd54566975/web5-go/dids/diddht/internal/bep44"
	"github.com/tbd54566975/web5-go/dids/diddht/internal/dns"
	"github.com/tbd54566975/web5-go/dids/diddht/internal/pkarr"
	"github.com/tv42/zbase32"
)

// relay is the internal interface used to publish Pakrr messages to the DHT
type relay interface {
	Put(didID string, payload *bep44.Message) error
	PutWithContext(ctx context.Context, didID string, payload *bep44.Message) error

	Fetch(didID string) (*bep44.Message, error)
	FetchWithContext(ctx context.Context, didID string) (*bep44.Message, error)
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

// dHTDidOptions is used to configure the creation of a `did:dht` DID; it's an internal representation of the options
type dHTDidOptions struct {
	algorithmID         string
	keyManager          crypto.KeyManager
	services            []*didcore.Service
	verificationMethods []didcore.VerificationMethod
	purposes            map[string][]didcore.Purpose
	relay               relay
}

type DHTDidOption func(o *dHTDidOptions)

// WithServices adds the provided services to the DID document.
func WithServices(services ...*didcore.Service) DHTDidOption {
	return func(o *dHTDidOptions) {
		o.services = append(o.services, services...)
	}
}

// WithVerificationMethod adds the provided verification method to the DID document.
func WithVerificationMethod(method didcore.VerificationMethod, purposes []didcore.Purpose) DHTDidOption {
	return func(o *dHTDidOptions) {
		o.verificationMethods = append(o.verificationMethods, method)
		for _, p := range purposes {
			if _, ok := o.purposes[method.ID]; !ok {
				o.purposes[method.ID] = []didcore.Purpose{}
			}
			o.purposes[method.ID] = append(o.purposes[method.ID], p)
		}
	}
}

// WithKeyManager sets the key manager to use for generating the DID's keypair.
func WithKeyManager(k crypto.KeyManager) DHTDidOption {
	return func(o *dHTDidOptions) {
		o.keyManager = k
	}
}

// WithRelay sets the relay to use for publishing the DID to the DHT.
func WithRelay(relayURL string, client *http.Client) DHTDidOption {
	return func(o *dHTDidOptions) {
		o.relay = pkarr.NewPkarrRelay(relayURL, client)
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
	o := dHTDidOptions{
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
	msgBytes, err := dns.MarshalDIDDocument(&document)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal did document to dns packet: %w", err)
	}

	// 6. Construct a signed BEP44 put message with the v value as a bencoded DNS packet from the prior step.
	seq := time.Now().Unix() / 1000

	signer := func(payload []byte) ([]byte, error) {
		return keyMgr.Sign(keyID, payload)
	}

	bep44Msg, err := bep44.NewSignedBEP44Message(msgBytes, seq, publicKeyBytes, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create signed bep44 message: %w", err)
	}

	if o.relay == nil {
		return nil, errors.New("no relay provided")
	}

	// 7. Submit the result of to the DHT via a Pkarr relay, or a Gateway, with the identifier created in step 1.
	if err := o.relay.PutWithContext(ctx, bdid.ID, bep44Msg); err != nil {
		return nil, fmt.Errorf("failed to punlish bep44 message to relay: %w", err)
	}

	bdid.Document = document
	return bdid, nil
}
