package diddht

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
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
		defaultRelay = pkarr.NewClient("", http.DefaultClient)
	})

	return defaultRelay
}

// CreateOption is the type returned from each individual option function
type CreateOption func(*createOptions)

// createOptions is a struct to hold options for creating a new 'did:web' BearerDID.
// Each option has a corresponding function that can be used by the caller to set the value of the option.
type createOptions struct {
	services    []didcore.Service
	privateKeys []privateKeyOption
	keyManager  crypto.KeyManager
	alsoKnownAs []string
	controllers []string
	relay       relay
}

// privateKeyOption is a struct to hold options for creating a new private key.
type privateKeyOption struct {
	algorithmID string
	purposes    []didcore.Purpose
}

// Service is used to add a service to the DID being created with the [Create] function.
// Note: Service can be passed to [Create] multiple times to add multiple services.
func Service(id string, svcType string, endpoint string) CreateOption {
	return func(o *createOptions) {
		// ensure that id follows relative DID URL requirements defined in did core spec:
		// https://www.w3.org/TR/did-core/#relative-did-urls
		var svcID string
		if id[0] == '#' || strings.HasPrefix(id, "did:") {
			svcID = id
		} else {
			svcID = "#" + id
		}

		svc := didcore.Service{ID: svcID, Type: svcType, ServiceEndpoint: endpoint}
		if o.services == nil {
			o.services = make([]didcore.Service, 0)
		}

		o.services = append(o.services, svc)
	}
}

// PrivateKey is used to add a private key to the DID being created with the [Create] function.
// Each PrivateKey provided will be used to generate a private key in the key manager and then
// added to the DID Document as a VerificationMethod.
func PrivateKey(algorithmID string, purposes ...didcore.Purpose) CreateOption {
	return func(o *createOptions) {
		keyOpts := privateKeyOption{algorithmID: algorithmID, purposes: purposes}

		if o.privateKeys == nil {
			o.privateKeys = make([]privateKeyOption, 0)
		}

		o.privateKeys = append(o.privateKeys, keyOpts)
	}
}

// KeyManager is used to set the key manager that will be used to generate the private keys for the DID.
func KeyManager(km crypto.KeyManager) CreateOption {
	return func(o *createOptions) {
		o.keyManager = km
	}
}

// AlsoKnownAs is used to set the 'alsoKnownAs' property of the DID Document.
// more details here: https://www.w3.org/TR/did-core/#also-known-as
func AlsoKnownAs(aka ...string) CreateOption {
	return func(o *createOptions) {
		o.alsoKnownAs = aka
	}
}

// Controllers is used to set the 'controller' property of the DID Document.
// more details here: https://www.w3.org/TR/did-core/#controller
func Controllers(controllers ...string) CreateOption {
	return func(o *createOptions) {
		o.controllers = controllers
	}
}

// Relay sets the relay to use for publishing the DID to the DHT.
func Relay(relayURL string, client *http.Client) CreateOption {
	return func(o *createOptions) {
		o.relay = pkarr.NewClient(relayURL, client)
	}
}

// Create creates a new `did:dht` DID and publishes it to the DHT network via a Pkarr relay.
//
// If no relay is passed in the options, Create uses a default Pkarr relay.
// Spec: https://did-dht.com/#create
func Create(opts ...CreateOption) (*did.BearerDID, error) {
	return CreateWithContext(context.Background(), opts...)
}

// CreateWithContext creates a new `did:dht` DID and publishes it to the DHT network via a Pkarr relay.
func CreateWithContext(ctx context.Context, opts ...CreateOption) (*did.BearerDID, error) {

	// 0. Set default options
	o := createOptions{
		relay:       getDefaultRelay(),
		keyManager:  crypto.NewLocalKeyManager(),
		privateKeys: []privateKeyOption{},
	}

	for _, opt := range opts {
		opt(&o)
	}

	if o.relay == nil {
		return nil, errors.New("no relay provided")
	}

	// 1. Generate an Ed25519 keypair
	keyMgr := o.keyManager

	keyID, err := keyMgr.GeneratePrivateKey(dsa.AlgorithmIDED25519)
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

	// create verification methods for each private key
	for _, pk := range o.privateKeys {
		// create private keys for the verification methods
		vmKeyID, err := keyMgr.GeneratePrivateKey(pk.algorithmID)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key for verification method: %w", err)
		}

		vmPublicKey, err := keyMgr.GetPublicKey(vmKeyID)
		if err != nil {
			return nil, fmt.Errorf("failed to get public key for verification method: %w", err)
		}

		vmPublicKeyBytes, err := dsa.PublicKeyToBytes(vmPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to convert public key to bytes for verification method: %w", err)
		}

		vmZbase32Encoded := zbase32.EncodeToString(vmPublicKeyBytes)
		newVM := didcore.VerificationMethod{
			ID:           "did:dht:" + vmZbase32Encoded,
			Type:         "JsonWebKey2020",
			Controller:   bdid.ID,
			PublicKeyJwk: &vmPublicKey,
		}

		document.AddVerificationMethod(newVM, didcore.Purposes(pk.purposes...))
	}

	for _, service := range o.services {
		s := service
		document.AddService(&s)
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

	bep44Msg, err := bep44.NewMessage(msgBytes, seq, publicKeyBytes, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create signed bep44 message: %w", err)
	}

	// 7. Submit the result of to the DHT via a Pkarr relay, or a Gateway, with the identifier created in step 1.
	if err := o.relay.PutWithContext(ctx, bdid.ID, bep44Msg); err != nil {
		return nil, fmt.Errorf("failed to punlish bep44 message to relay: %w", err)
	}

	bdid.Document = document
	return bdid, nil
}
