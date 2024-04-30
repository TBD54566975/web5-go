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

// FieldPath represents the valid paths to a field in a VC
type FieldPath struct {
	Paths []string
}

// SelectCredentials selects the VCs that satisfy the constraints specified in the Presentation Definition
func SelectCredentials(vcJwts []string, pd PresentationDefinition) ([]string, error) {

	fieldPaths := make(map[string]FieldPath)
	fieldFilters := make(map[string]Filter)

	// Extract the field paths and filters from the input descriptors
	for _, inputDescriptor := range pd.InputDescriptors {
		for _, field := range inputDescriptor.Constraints.Fields {
			token := generateRandomToken()
			paths := field.Path
			fieldPaths[token] = FieldPath{Paths: paths}

			if field.Filter != nil {
				fieldFilters[token] = *field.Filter
			}
		}
	}

	selectionCandidates := make(map[string]interface{})
	// Find vcJwts whose fields match the fieldPaths
	for _, vcJwt := range vcJwts {

		decoded, err := vc.Decode[vc.Claims](vcJwt)
		if err != nil {
			return nil, fmt.Errorf("failed to decode vcJwt: %w", err)
		}
		for _, fieldToken := range fieldPaths {
			for _, path := range fieldToken.Paths {
				marshaledVcJwt, _ := json.Marshal(decoded.JWT.Claims)
				var jsondata interface{}
				err := json.Unmarshal(marshaledVcJwt, &jsondata)
				if err != nil {
					fmt.Println("Error unmarshaling JSON:", err)
					continue
				}
				fmt.Printf("Trying to find %s in %+v\n\n", path, decoded.VC)
				value, err := jsonpath.Get(path, jsondata)
				if err != nil {
					fmt.Printf("for path %s\n field was NOT found in VC: %+v\n\n", path, decoded.VC)
					continue
				}

				// selectionCandidates[fieldToken.Token] = result
				selectionCandidates[vcJwt] = value
				fmt.Printf("for path %s\n field WAS found in VC: %+v\n\n", path, decoded.VC.CredentialSubject)
				break
			}
		}
	}

	var matchingVcJWTs []string

	// If no field filters are specified in PD, return all the vcJwts that matched the fieldPaths (selectionCandidates keys)
	if len(fieldFilters) == 0 {
		for vcJwt := range selectionCandidates {
			matchingVcJWTs = append(matchingVcJWTs, vcJwt)
		}
		return matchingVcJWTs, nil
	}

	// Filter further for vcJwts whose fields match the fieldFilters
	for vcJwt, value := range selectionCandidates {

		for _, filter := range fieldFilters {
			fmt.Println(value)
			filterSatisfied := satisfiesFieldFilter(value, filter)
			if filterSatisfied {
				fmt.Printf("Filter satisfied! %v", value)
				matchingVcJWTs = append(matchingVcJWTs, vcJwt)
			} else {
				fmt.Printf("Filter NOT satisfied. %v", value)
			}
		}
	}

	return matchingVcJWTs, nil
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
		err := json.Unmarshal(resultBytes, &fieldValue)
		fmt.Printf("fieldValue: %s filter.Const %s\n", fieldValue, filter.Const)
		if err == nil && fieldValue == filter.Const {
			return true
		}
		return false
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
				oneMatch := false
				for _, item := range arrayVal {
					// recursively check for filter.Contains in each item
					if satisfiesFieldFilter(item, *filter.Contains) {
						oneMatch = true
					}
				}
				return oneMatch
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
