package dns

import (
	"encoding/base64"
	"errors"
	"net/url"
	"sort"
	"strings"

	"github.com/tbd54566975/web5-go/crypto/dsa"
	"github.com/tbd54566975/web5-go/dids/didcore"
	"golang.org/x/net/dns/dnsmessage"
)

// MarshalDIDDocument packs a DID document into a TXT DNS resource records and adds to the DNS message Answers
func MarshalDIDDocument(d *didcore.Document) ([]byte, error) {

	// create root record
	var msg dnsmessage.Message

	// get sorted VM IDs
	sortedIDs := pluckSort(d.VerificationMethod)
	vmIDToK := map[string]string{}

	vmBep44Keys := []string{}
	for k, id := range sortedIDs {
		_k := fmt.Sprintf("k%d", k)
		vmIDToK[id] = _k
		vmBep44Keys = append(vmBep44Keys, _k)
	}

	sToK := map[string]string{}
	sKeys := []string{}
	for k, v := range d.Service {
		_k := fmt.Sprintf("s%d", k)
		sToK[v.ID] = _k
		sKeys = append(sKeys, _k)
	}

	rootProps := map[string][]string{
		"v":    {"1"},
		"id":   {d.ID},
		"vm":   vmBep44Keys,
		"auth": methodsToKeys(d.Authentication, vmIDToK),
		"asm":  methodsToKeys(d.AssertionMethod, vmIDToK),
		"agm":  methodsToKeys(d.KeyAgreement, vmIDToK),
		"inv":  methodsToKeys(d.CapabilityInvocation, vmIDToK),
		"del":  methodsToKeys(d.CapabilityDelegation, vmIDToK),
		"srv":  sKeys,
		"cnt":  d.Controller,
		"aka":  d.AlsoKnownAs,
	}

	rootRecordHeader := dnsmessage.ResourceHeader{
		Name: dnsmessage.MustNewName("_did."),
		Type: dnsmessage.TypeTXT,
		TTL:  7200,
	}

	rootPropsSerialized := []string{}
	for k, v := range rootProps {
		if len(v) <= 0 {
			continue
		}
		prop := fmt.Sprintf("%s=%s", k, strings.Join(v, ","))
		rootPropsSerialized = append(rootPropsSerialized, prop)
	}

	rootTXTRes := dnsmessage.TXTResource{
		TXT: []string{strings.Join(rootPropsSerialized, ";")},
	}

	msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: rootRecordHeader, Body: &rootTXTRes})

	// add verification methods to dns message
	for _, v := range d.VerificationMethod {
		// look for the key after the # in the verification method ID
		key, ok := vmIDToK[v.ID]
		if !ok {
			// TODO handle error
			continue
		}
		buf, err := MarshalVerificationMethod(&v)
		if err != nil {
			return nil, err
		}

		name, err := dnsmessage.NewName(fmt.Sprintf("_%s._did.", key))
		if err != nil {
			return nil, err
		}
		header := dnsmessage.ResourceHeader{
			Name: name,
			Type: dnsmessage.TypeTXT,
			TTL:  7200,
		}

		resource := dnsmessage.TXTResource{
			TXT: []string{buf},
		}

		msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: header, Body: &resource})
	}

	// add services to dns message
	for _, s := range d.Service {
		key, ok := sToK[s.ID]
		if !ok {
			// TODO handle error
			continue
		}
		if err := MarshalService(key, s, &msg); err != nil {
			return nil, err
		}
	}

	msgByes, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	return msgByes, nil
}

// UnmarshalDIDDocument unpacks the TXT DNS resource records and returns a DID document
func UnmarshalDIDDocument(didID string, payload []byte) (*didcore.Document, error) {
	decoder, err := parseDNSDID(payload)
	if err != nil {
		return nil, err
	}

	doc, err := decoder.DIDDocument(didID)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

// MarshalVerificationMethod packs a verification method into a TXT DNS resource record and adds to the DNS message Answers
func MarshalVerificationMethod(vm *didcore.VerificationMethod) (string, error) {
	keyBytes, err := dsa.PublicKeyToBytes(*vm.PublicKeyJwk)
	if err != nil {
		return "", err
	}

	algID, err := dsa.AlgorithmID(vm.PublicKeyJwk)
	if err != nil {
		return "", err
	}
	t, ok := algToDhtIndex[algID]
	if !ok {
		return "", fmt.Errorf("unsupported algorithm")
	}

	props := []string{
		"id=" + vm.ID,
		"t=" + t,
		"k=" + base64.RawURLEncoding.EncodeToString(keyBytes),
	}

	if len(vm.Controller) > 0 {
		props = append(props, "c="+vm.Controller)
	}

	dhtEncodedVM := strings.Join(props, ";")

	return dhtEncodedVM, nil

}

func MarshalService(dhtDNSkey string, s *didcore.Service, msg *dnsmessage.Message) error {
	name, err := dnsmessage.NewName(fmt.Sprintf("_%s._did.", dhtDNSkey))
	if err != nil {
		return err
	}
	header := dnsmessage.ResourceHeader{
		Name: name,
		Type: dnsmessage.TypeTXT,
		TTL:  7200,
	}

	rawData := fmt.Sprintf("id=%s;t=%s;se=%s", s.ID, s.Type, s.ServiceEndpoint)
	resource := dnsmessage.TXTResource{
		TXT: []string{rawData},
	}

	msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: header, Body: &resource})
	return nil
}

// UnmarshalVerificationMethod unpacks the TXT DNS resource encoded verification method
func UnmarshalVerificationMethod(data string, vm *didcore.VerificationMethod) error {
	propertyMap, err := parseTXTRecordData(data)
	if err != nil {
		return err
	}

	vm.Type = "JsonWebKey2020"

	var key string
	var algorithmID string
	for property, v := range propertyMap {
		switch property {
		// According to https://did-dht.com/#verification-methods, this should not be a list
		case "id":
			vm.ID = strings.Join(v, "")
		case "t": // Index of the key type https://did-dht.com/registry/index.html#key-type-index
			algorithmID, _ = dhtIndexToAlg[strings.Join(v, "")]
		case "k": // unpadded base64URL representation of the public key
			key = strings.Join(v, "")
		case "c": // the controller is optional
			vm.Controller = strings.Join(v, "")
		default:
			continue
		}
	}

	if len(key) == 0 || len(algorithmID) == 0 {
		return errors.New("unable to parse public key")
	}

	// RawURLEncoding is the same as URLEncoding but omits padding.
	// Decoding and reencoding to make sure there is no padding
	keyBytes, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return err
	}

	if len(keyBytes) == 0 {
		return errors.New("malformed public key")
	}

	j, err := dsa.BytesToPublicKey(algorithmID, keyBytes)
	if err != nil {
		return err
	}
	vm.PublicKeyJwk = &j

	// validate all the parts exist
	if len(vm.ID) == 0 || vm.PublicKeyJwk == nil {
		return errors.New("malformed verification method representation")
	}

	return nil
}

// UnmarshalService unpacks the TXT DNS resource encoded service
func UnmarshalService(data string, s *didcore.Service) error {
	propertyMap, err := parseTXTRecordData(data)
	if err != nil {
		return err
	}
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
					return errors.New("invalid service endpoint")
				}
				validEndpoints = append(validEndpoints, uri)
			}
			s.ServiceEndpoint = strings.Join(validEndpoints, ",")
		default:
			continue
		}
	}

	return nil
}

func pluckSort(hayStack []didcore.VerificationMethod) []string {
	ids := []string{}
	for _, v := range hayStack {
		ids = append(ids, v.ID)
	}
	sort.Strings(ids)
	return ids
}

// methodsToKeys takes a list of method indices and returns the corresonding verification method _kN keys
func methodsToKeys(methods []string, idToKey map[string]string) []string {
	keys := []string{}
	for _, v := range methods {
		k, ok := idToKey[v]
		if ok {
			keys = append(keys, k)
		}
	}
	return keys
}
