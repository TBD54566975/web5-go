package pexv2

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/PaesslerAG/jsonpath"
	"github.com/tbd54566975/web5-go/vc"
)

type FieldToken struct {
	Token string
	Paths []string
}

func SelectCredentials(vcJwts []string, pd PresentationDefinition) ([]string, error) {

	fieldTokens := make(map[string]FieldToken)
	jsonSchemas := make(map[string]Filter)

	for _, inputDescriptor := range pd.InputDescriptors {
		for _, field := range inputDescriptor.Constraints.Fields {
			token := generateRandomToken() // field.ID
			paths := field.Path
			fieldTokens[token] = FieldToken{Token: token, Paths: paths}

			if field.Filter != nil {
				jsonSchemas[token] = *field.Filter
			}
		}
	}

	selectionCandidates := make(map[string]interface{})
	for i, vcJwt := range vcJwts {
		if i == 1 || i == 3 {
			fmt.Printf("Decoding VC JWT input index, this one should match %d\n\n", i)
		}

		decoded, err := vc.Decode[vc.Claims](vcJwt)
		if err != nil {
			return nil, fmt.Errorf("failed to decode vcJwt: %w", err)
		}
		for _, fieldToken := range fieldTokens {
			for _, path := range fieldToken.Paths {
				marshaledVcJwt, _ := json.Marshal(decoded.JWT.Claims)
				var jsondata interface{}
				err := json.Unmarshal(marshaledVcJwt, &jsondata)
				if err != nil {
					fmt.Println("Error unmarshaling JSON:", err)
					continue
				}
				fmt.Printf("Trying to find %s in %+v\n\n", path, decoded.VC)
				result, err := jsonpath.Get(path, jsondata)
				if err != nil {
					fmt.Printf("for path %s\n field was NOT found in VC: %+v\n\n", path, decoded.VC)
					continue
				}

				// selectionCandidates[fieldToken.Token] = result
				selectionCandidates[vcJwt] = result
				fmt.Printf("for path %s\n field WAS found in VC: %+v\n\n", path, decoded.VC.CredentialSubject)
				break
			}
		}
	}

	var answer []string
	for vcJwt, result := range selectionCandidates {

		for _, jsonSchema := range jsonSchemas {
			filterSatisfied := satisfiesFieldFilter(result, jsonSchema)
			if filterSatisfied {
				fmt.Println("Filter satisfied!")
				answer = append(answer, vcJwt)
				return answer, nil
			} else {
				fmt.Println("Filter not satisfied")
				return []string{}, nil
			}
		}
	}

	if len(answer) == 0 {
		// Iterate over the map and append each key to the keys slice
		for key := range selectionCandidates {
			answer = append(answer, key)
		}
	}

	return answer, nil
}

func satisfiesFieldFilter(fieldValue interface{}, filter Filter) bool {
	resultBytes, err := json.Marshal(fieldValue)
	if err != nil {
		fmt.Println("Error marshaling result:", err)
		return false
	}

	// Check if the field value matches the constant if specified
	if filter.Const != "" {
		var fieldValue string
		if err := json.Unmarshal(resultBytes, &fieldValue); err == nil && fieldValue == filter.Const {
			return true
		}
	}

	// Type checking and pattern matching
	if filter.Type != "" || filter.Pattern != "" {
		switch filter.Type {
		case "string":
			var strVal string
			if err := json.Unmarshal(resultBytes, &strVal); err != nil {
				return false
			}
			if filter.Pattern != "" {
				match, _ := regexp.MatchString(filter.Pattern, strVal)
				return match
			}
		case "number":
			var numVal float64
			if err := json.Unmarshal(resultBytes, &numVal); err != nil {
				return false
			}
		case "array":
			var arrayVal []interface{}
			if err := json.Unmarshal(resultBytes, &arrayVal); err != nil {
				return false
			}
			if filter.Contains != nil {
				for _, item := range arrayVal {
					if satisfiesFieldFilter(item, *filter.Contains) { // Assuming recursive check on each item
						return true
					}
				}
			}
		default:
			// Unsupported type
			return false
		}
	}

	return true
}

func generateRandomToken() string {
	// Create a byte slice of length 16.
	b := make([]byte, 16)

	// Read random bytes into the slice.
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	// Encode the byte slice to a hexadecimal string.
	return hex.EncodeToString(b)
}

/*
loop 1: create json schema using PD
loop 2: loop through
*/

type JwtNodePair struct {
	VcJwt string
	Node  []byte
}
