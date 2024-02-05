package didweb

import (
	"fmt"

	"github.com/tbd54566975/web5-go/crypto"
	"github.com/tbd54566975/web5-go/crypto/dsa"
	_did "github.com/tbd54566975/web5-go/dids/did"
	"github.com/tbd54566975/web5-go/dids/didcore"
)

type privateKeyOption struct {
	algorithmID string
	purposes    []string
}

type createOptions struct {
	services    []didcore.Service
	privateKeys []privateKeyOption
	keyManager  crypto.KeyManager
}

type CreateOption func(*createOptions)

func Service(id string, svcType string, endpoint string) CreateOption {
	return func(o *createOptions) {
		svc := didcore.Service{ID: id, Type: svcType, ServiceEndpoint: endpoint}
		if o.services == nil {
			o.services = make([]didcore.Service, 0)
		}

		o.services = append(o.services, svc)
	}
}

func PrivateKey(algorithmID string, purposes ...string) CreateOption {
	return func(o *createOptions) {
		keyOpts := privateKeyOption{algorithmID: algorithmID, purposes: purposes}

		if o.privateKeys == nil {
			o.privateKeys = make([]privateKeyOption, 0)
		}

		o.privateKeys = append(o.privateKeys, keyOpts)
	}
}

func KeyManager(km crypto.KeyManager) CreateOption {
	return func(o *createOptions) {
		o.keyManager = km
	}
}

func Create(domain string, opts ...CreateOption) (_did.BearerDID, error) {
	options := &createOptions{
		keyManager: crypto.NewLocalKeyManager(),
		privateKeys: []privateKeyOption{
			{
				algorithmID: dsa.AlgorithmIDED25519,
			},
		},
	}

	for _, opt := range opts {
		opt(options)
	}

	did, err := _did.Parse("did:web:" + domain)
	if err != nil {
		return _did.BearerDID{}, fmt.Errorf("invalid domain: %w", err)
	}

	document := didcore.Document{
		ID: did.URI,
	}

	for _, keyOpts := range options.privateKeys {
		keyID, err := options.keyManager.GeneratePrivateKey(keyOpts.algorithmID)
		if err != nil {
			return _did.BearerDID{}, fmt.Errorf("failed to generate %s private key: %w", keyOpts.algorithmID, err)
		}

		publicKeyJWK, err := options.keyManager.GetPublicKey(keyID)
		if err != nil {
			return _did.BearerDID{}, fmt.Errorf("failed to get public key for private key %s: %w", keyID, err)
		}

		vmID, err := publicKeyJWK.ComputeThumbprint()
		if err != nil {
			return _did.BearerDID{}, fmt.Errorf("failed to generate verification method id: %w", err)
		}

		vm := didcore.VerificationMethod{
			ID:           "#" + vmID,
			Type:         "JsonWebKey2020",
			Controller:   did.URI,
			PublicKeyJwk: &publicKeyJWK,
		}

		document.AddVerificationMethod(vm, didcore.Purposes(keyOpts.purposes...))

	}

	for _, svc := range options.services {
		document.AddService(&svc)
	}

	return _did.BearerDID{
		DID:        did,
		KeyManager: options.keyManager,
		Document:   document,
	}, nil
}
