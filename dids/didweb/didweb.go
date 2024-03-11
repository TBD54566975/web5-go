package didweb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/tbd54566975/web5-go/crypto"
	"github.com/tbd54566975/web5-go/crypto/dsa"
	_did "github.com/tbd54566975/web5-go/dids/did"
	"github.com/tbd54566975/web5-go/dids/didcore"
)

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

// Create creates a new 'did:web' BearerDID with the given domain and options provided.
// If no options are provided, a default key manager will be used to generate a single ED25519 key pair.
// The resulting public key will be added to the DID Document as a VerificationMethod.
// More information regarding did:web can be found here: https://w3c-ccg.github.io/did-method-web/
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

	// normalize domain by adding scheme if not present. otherwise [url.Parse] won't error but we also won't get
	// necessary part separation.
	var normalizedDomain string
	if !strings.HasPrefix(domain, "http") {
		normalizedDomain = "http://" + domain
	} else {
		normalizedDomain = domain
	}

	parsedDomain, err := url.Parse(normalizedDomain)
	if err != nil {
		return _did.BearerDID{}, fmt.Errorf("failed to parse domain: %w", err)
	}

	var methodSpecificID = parsedDomain.Hostname()
	if parsedDomain.Port() != "" {
		methodSpecificID = methodSpecificID + "%3A" + parsedDomain.Port()
	}

	if parsedDomain.Path != "" {
		idPath := strings.ReplaceAll(parsedDomain.Path, "/", ":")
		methodSpecificID += strings.TrimSuffix(idPath, ":")
	}

	did, err := _did.Parse("did:web:" + methodSpecificID)
	if err != nil {
		return _did.BearerDID{}, fmt.Errorf("invalid domain: %w", err)
	}

	document := didcore.Document{
		ID: did.URI,
	}

	if len(options.alsoKnownAs) > 0 {
		document.AlsoKnownAs = options.alsoKnownAs
	}

	if len(options.controllers) > 0 {
		document.Controller = options.controllers
	}

	for idx, keyOpts := range options.privateKeys {
		keyID, err := options.keyManager.GeneratePrivateKey(keyOpts.algorithmID)
		if err != nil {
			return _did.BearerDID{}, fmt.Errorf("failed to generate %s private key: %w", keyOpts.algorithmID, err)
		}

		publicKeyJWK, err := options.keyManager.GetPublicKey(keyID)
		if err != nil {
			return _did.BearerDID{}, fmt.Errorf("failed to get public key for private key %s: %w", keyID, err)
		}

		vm := didcore.VerificationMethod{
			ID:           "#" + strconv.Itoa(idx),
			Type:         "JsonWebKey2020",
			Controller:   did.URI,
			PublicKeyJwk: &publicKeyJWK,
		}

		document.AddVerificationMethod(vm, didcore.Purposes(keyOpts.purposes...))

	}

	for _, svc := range options.services {
		document.AddService(&svc) //nolint:gosec
	}

	return _did.BearerDID{
		DID:        did,
		KeyManager: options.keyManager,
		Document:   document,
	}, nil
}

// DecodeID takes a did:web's identifier (the third part, after the method) and returns the web URL per the [spec]
//
// [spec]: https://w3c-ccg.github.io/did-method-web/#read-resolve
func DecodeID(id string) string {
	var domain string

	// "1. Replace ":" with "/" in the method specific identifier to obtain the fully qualified domain name and optional path."
	domain = strings.ReplaceAll(id, ":", "/")

	// "2. If the domain contains a port percent decode the colon."
	domain = strings.Replace(domain, "%3A", ":", 1)

	// "3. Generate an HTTPS URL to the expected location of the DID document by prepending https://."
	domain = "https://" + domain

	// "4. If no path has been specified in the URL, append /.well-known."
	if strings.Count(domain, "/") == 2 {
		domain += "/.well-known"
	}

	// "5. Append /did.json to complete the URL."
	domain += "/did.json"

	return domain
}

// Resolver is a type to implement resolution
type Resolver struct{}

// ResolveWithContext the provided DID URI (must be a did:web) as per the [spec]
//
// [spec]: https://w3c-ccg.github.io/did-method-web/#read-resolve
func (r Resolver) ResolveWithContext(ctx context.Context, uri string) (didcore.ResolutionResult, error) {
	did, err := _did.Parse(uri)
	if err != nil {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	if did.Method != "web" {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	domain := DecodeID(did.ID)

	parsedURL, err := url.ParseRequestURI(domain)
	if err != nil {
		return didcore.ResolutionResult{}, err
	}

	if parsedURL.Scheme != "https" {
		return didcore.ResolutionResult{}, fmt.Errorf("invalid URL scheme: %s", parsedURL.Scheme)
	}

	// TODO item 6 from https://w3c-ccg.github.io/did-method-web/#read-resolve https://github.com/TBD54566975/web5-go/issues/94
	// TODO item 7 from https://w3c-ccg.github.io/did-method-web/#read-resolve https://github.com/TBD54566975/web5-go/issues/95

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, domain, nil)
	if err != nil {
		return didcore.ResolutionResult{}, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return didcore.ResolutionResult{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return didcore.ResolutionResult{}, fmt.Errorf("failed to read response body: %w", err)
	}

	var document didcore.Document
	err = json.Unmarshal(body, &document)
	if err != nil {
		return didcore.ResolutionResult{}, fmt.Errorf("failed to deserialize document: %w", err)
	}

	return didcore.ResolutionResultWithDocument(document), nil
}

// Resolve the provided DID URI (must be a did:web) as per the [spec]
//
// [spec]: https://w3c-ccg.github.io/did-method-web/#read-resolve
func (r Resolver) Resolve(uri string) (didcore.ResolutionResult, error) {
	return r.ResolveWithContext(context.Background(), uri)
}
