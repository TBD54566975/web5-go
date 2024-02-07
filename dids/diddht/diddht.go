package diddht

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/tbd54566975/web5-go/dids/didcore"
)

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
