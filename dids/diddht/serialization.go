package diddht

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/tbd54566975/web5-go/crypto/dsa"
	"github.com/tbd54566975/web5-go/dids/didcore"
)

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

	if len(key) <= 0 || len(algorithmID) <= 0 {
		return fmt.Errorf("unable to parse public key")
	}

	// RawURLEncoding is the same as URLEncoding but omits padding.
	// Decoding and reencoding to make sure there is no padding
	keyBytes, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return err
	}

	if len(keyBytes) <= 0 {
		return fmt.Errorf("malformed public key")
	}

	j, err := dsa.BytesToPublicKey(algorithmID, keyBytes)
	if err != nil {
		return err
	}
	vm.PublicKeyJwk = &j

	// validate all the parts exist
	if len(vm.ID) <= 0 || vm.PublicKeyJwk == nil {
		return fmt.Errorf("malformed verification method representation")
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
					return fmt.Errorf("invalid service endpoint")
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
