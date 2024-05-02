package pexv2

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/PaesslerAG/jsonpath"
	"github.com/tbd54566975/web5-go/vc"
	jsonschema "github.com/xeipuuv/gojsonschema"
)

// FieldPath represents the valid paths to a field in a VC
type FieldPath struct {
	Token string
	Paths []string
}

// todo only need to meet one of the input descriptors for a vcjwt to be selected
// 	for selectCredentials, if there are multiple input descriptors, each vcJwt must meet at least 1 of them

// for satisfiesPD() to not throw, i need to pass in
// 1. a vc with btcAddress + a vc with dogeAddress
// 2. a vc with BOTH btcAddress and dogeAddress
// 3. a combination of the above (can also throw in a vc with other stuff i.e. name)
// SelectCredentials selects the VCs that satisfy the constraints specified in the Presentation Definition
func SelectCredentials(vcJwts []string, pd PresentationDefinition) ([]string, error) {

	fieldTokens := make(map[string]TokenPath)

	// Extract the field paths and filters from the input descriptors
	for _, inputDescriptor := range pd.InputDescriptors {
		schema := map[string]interface{}{
			"$schema":    "http://json-schema.org/draft-07/schema#",
			"type":       "object",
			"properties": map[string]interface{}{},
		}

		for _, field := range inputDescriptor.Constraints.Fields {
			token := generateRandomToken()
			paths := field.Path
			fieldTokens[token] = TokenPath{Token: token, Paths: paths}

			if field.Filter != nil {
				addFieldToSchema(schema, token, field)
			}
		}
	}

	fieldTokensJson, _ := json.MarshalIndent(fieldTokens, "", "    ")
	fmt.Printf("Token to Paths: %+v\n\n\n\n", string(fieldTokensJson))

	var matchingVcJWTs []string

	// Find vcJwts whose fields match the fieldPaths
	for i, vcJwt := range vcJwts {
		fmt.Printf("\tvcJwt: number %d, %s\n\n\n\n\n\n", i, vcJwt)
		decoded, err := vc.Decode[vc.Claims](vcJwt)
		if err != nil {
			return nil, fmt.Errorf("failed to decode vcJwt: %w", err)
		}
		selectionCandidates := make(map[string]interface{})
		for _, tokenPath := range fieldTokens {
			for _, path := range tokenPath.Paths {
				vcJson := getVcJsonData(decoded)
				value, err := jsonpath.Get(path, vcJson)
				if err != nil {
					fmt.Printf("Unable to find value in the path %s in vcJson %+v. Error: %v\n\n\n", path, vcJson, err)
					continue
				}

				fmt.Printf("putting token %s and paths %s with value %s in selectionCandidates\n", tokenPath.Token, tokenPath.Paths, value)

				selectionCandidates[tokenPath.Token] = value
				break
			}
		}

		// todo this is enforcing that 1 vcJwt must match ALL input descriptor paths. need to change this to 1 vcJwt must match at least 1 input descriptor path
		if len(fieldTokens) == len(selectionCandidates) {

			properties, _ := schema["properties"].(map[string]interface{})

			if len(properties) > 0 {
				schemaLoader := getSchemaLoader(schema, selectionCandidates)
				documentLoader := jsonschema.NewGoLoader(selectionCandidates)

				result, err := jsonschema.Validate(schemaLoader, documentLoader)
				if err != nil {
					fmt.Println("Error validating schema:", err)
				}

				if result.Valid() {
					fmt.Printf("The document is valid\n\n\n\n")
					matchingVcJWTs = append(matchingVcJWTs, vcJwt)

				} else {
					fmt.Printf("The document is not valid. see errors :")
					for _, desc := range result.Errors() {
						fmt.Printf("- %s\n", desc)
					}
					fmt.Print("\n\n\n\n")
				}
			} else {
				matchingVcJWTs = append(matchingVcJWTs, vcJwt)
			}
		}
	}

	return matchingVcJWTs, nil

}

func getSchemaLoader(schema map[string]interface{}, selectionCandidates map[string]interface{}) jsonschema.JSONLoader {
	schemaJSON, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling schema:", err)
	}
	fmt.Printf("Schema: %s\n", string(schemaJSON))
	fmt.Printf("Selection Candidates: %v\n", selectionCandidates)

	schemaLoader := jsonschema.NewStringLoader(string(schemaJSON))
	return schemaLoader
}

func addFieldToSchema(schema map[string]interface{}, token string, field Field) {
	properties, ok := schema["properties"].(map[string]interface{})
	if !ok {
		fmt.Printf("unable to assert 'properties' as map[string]interface{}")
	}
	properties[token] = field.Filter
}

func getVcJsonData(decoded vc.DecodedVCJWT[vc.Claims]) interface{} {
	marshaledVcJwt, _ := json.Marshal(decoded.JWT.Claims)
	var jsondata interface{}
	err := json.Unmarshal(marshaledVcJwt, &jsondata)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return interface{}(nil)
	}
	return jsondata
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
