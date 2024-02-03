package diddht

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/tbd54566975/web5-go/crypto/dsa"
	"github.com/tbd54566975/web5-go/dids/did"
	"github.com/tbd54566975/web5-go/dids/didcore"
	"github.com/tv42/zbase32"
)

var txtEntityNames = map[string]struct{}{
	"vm":   {},
	"auth": {},
	"asm":  {},
	"agm":  {},
	"inv":  {},
	"del":  {},
}

var relationshipDNStoDID = map[string]string{
	"auth": "authentication",
	"asm":  "assertionMethod",
	"agm":  "keyAgreement",
	"inv":  "capabilityInvocation",
	"del":  "capabilityDelegation",
}

var keyTypes = map[string]string{
	"0": dsa.AlgorithmIDED25519,
	"1": dsa.AlgorithmIDSECP256K1,
	"2": dsa.AlgorithmIDSECP256K1,
}

type Resolver struct {
	relay  string
	client *http.Client
}

func NewResolver(relay string, client *http.Client) *Resolver {
	return &Resolver{
		relay:  relay,
		client: client,
	}
}

// dhtDIDRecord is used to structure the DNS representation of a DID
type dhtDIDRecord struct {
	rootRecord string
	records    map[string]string
}

func (rec *dhtDIDRecord) DIDDocument(didURI string) *didcore.Document {
	relationshipMap := parseVerificationRelationships(rec.rootRecord)

	// Now we have a did in a dns record. yay
	document := &didcore.Document{
		ID: didURI,
	}

	// Now create the did document
	for name, data := range rec.records {

		switch {
		case strings.HasPrefix(name, "_k"):
			vMethod, err := UnmarshalVerificationMethod(data)
			if err != nil {
				// TODO handle error
			}

			// extracting kN from _kN._did
			entryId := strings.Split(name, ".")[0][1:]
			relationships, ok := relationshipMap[entryId]

			if !ok {
				// no relationships
				continue
			}

			opts := []string{}
			for _, r := range relationships {
				if o, ok := relationshipDNStoDID[r]; ok {
					opts = append(opts, o)
				}
			}

			document.AddVerificationMethod(
				*vMethod,
				didcore.Purposes(opts...),
			)
		case strings.HasPrefix(name, "_s"):
			s := UnmarshalService(data)
			document.AddService(s)
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

	return document
}

// Resolve resolves a DID using the DHT method
func (r *Resolver) Resolve(uri string) (didcore.ResolutionResult, error) {

	// 1. Parse URI and make sure it's a DHT method
	did, err := did.Parse(uri)
	if err != nil {
		// TODO log err
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	if did.Method != "dht" {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	// 2. ensure did ID is zbase32
	identifier, err := zbase32.DecodeString(did.ID)
	if err != nil {
		// TODO log err
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	if len(identifier) <= 0 {
		// return nil, fmt.Errorf("no bytes decoded from zbase32 identifier %s", did.ID)
		// TODO log err
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	// 3. fetch bep44 encoded did document
	res, err := r.client.Get(fmt.Sprintf("%s/%s", r.relay, did.ID))
	if err != nil {
		// TODO log err
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		// TODO log err
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	didRecord, err := parseDNSDID(data)
	if err != nil {
		// TODO log err
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	document := didRecord.DIDDocument(uri)
	return didcore.ResolutionResultWithDocument(*document), nil
}

// parseDNSDID takes the bytes of the DNS representation of a DID and creates an internal representation
// used to create a DID document
func parseDNSDID(data []byte) (*dhtDIDRecord, error) {
	var p dnsmessage.Parser
	if _, err := p.Start(data); err != nil {
		return nil, err
	}

	didRecord := dhtDIDRecord{
		records: make(map[string]string),
	}

	// need to skip questions to move the index to the right place to read answers
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}

	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}

		if h.Type != dnsmessage.TypeTXT {
			continue
		}

		value, err := p.TXTResource()
		if err != nil {
			// TODO check what kind of error and see if this should fail
		}

		name := h.Name.String()
		fullTxtRecord := strings.Join(value.TXT, "")
		if strings.HasPrefix(name, "_did") {
			didRecord.rootRecord = fullTxtRecord
			continue
		}

		if _, ok := didRecord.records[h.Name.String()]; !ok {

		}
		didRecord.records[h.Name.String()] = fullTxtRecord
	}

	return &didRecord, nil
}

// TODO on the diddhtrecord we should validate the minimum reqs for a valid did
func parseVerificationRelationships(rootRecord string) map[string][]string {
	rootRecordProps := parseTXTRecordData(rootRecord)

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

	return relationshipMap
}

func parseTXTRecordData(data string) map[string][]string {
	result := map[string][]string{}
	fields := strings.Split(data, ";")
	for _, field := range fields {
		kv := strings.Split(field, "=")
		k, v := kv[0], strings.Split(kv[1], ",")
		current, ok := result[k]
		if ok {
			v = append(current, v...)
		}
		result[k] = v
	}

	return result
}

func Create(did *didcore.Document) {

}

// UnmarshalVerificationMethod unpacks the TXT DNS resource encoded verification method
func UnmarshalVerificationMethod(data string) (*didcore.VerificationMethod, error) {
	propertyMap := parseTXTRecordData(data)

	vm := &didcore.VerificationMethod{}
	var key string
	var algorithmID string
	for property, v := range propertyMap {
		switch property {
		// According to https://did-dht.com/#verification-methods, this should not be a list
		case "id":
			vm.ID = strings.Join(v, "")
		case "t": // Index of the key type https://did-dht.com/registry/index.html#key-type-index
			algorithmID, _ = keyTypes[strings.Join(v, "")]
		case "k": // unpadded base64URL representation of the public key
			key = strings.Join(v, "")
		case "c": // the controller is optional
			vm.Controller = strings.Join(v, "")
		default:
			continue
		}
	}

	if len(key) <= 0 || len(algorithmID) <= 0 {
		return nil, fmt.Errorf("unable to parse public key")
	}

	// RawURLEncoding is the same as URLEncoding but omits padding.
	// Decoding and reencoding to make sure there is no padding
	keyBytes, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	if len(keyBytes) <= 0 {
		return nil, fmt.Errorf("empty key")
	}

	j, err := dsa.BytesToPublicKey(algorithmID, keyBytes)
	if err != nil {
		return nil, err
	}
	vm.PublicKeyJwk = &j

	// validate all the parts exist
	if len(vm.ID) <= 0 || vm.PublicKeyJwk == nil {
		return nil, fmt.Errorf("malformed verification method representation")
	}

	return vm, nil
}

func UnmarshalService(data string) *didcore.Service {
	propertyMap := parseTXTRecordData(data)

	s := &didcore.Service{}
	for property, v := range propertyMap {
		switch property {
		case "id":
			s.ID = strings.Join(v, "")
		case "t":
			s.Type = strings.Join(v, "")
		case "se":
			validEndpoints := []string{}
			for _, uri := range v {
				if _, err := url.ParseRequestURI(uri); err != nil {
					validEndpoints = append(validEndpoints, uri)
				}
			}
			s.ServiceEndpoint = strings.Join(validEndpoints, ",")
		default:
			continue
		}
	}

	return s
}
