package pexv2

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/PaesslerAG/jsonpath"
	"github.com/tbd54566975/web5-go/vc"
	jsonschema "github.com/xeipuuv/gojsonschema"
)

type tokenPath struct {
	Token string
	Paths []string
}

// SelectCredentials selects vcJWTs based on the constraints defined in the presentation definition
func SelectCredentials(vcJWTs []string, pd PresentationDefinition) ([]string, error) {

	result := make([]string, 0)
	for _, inputDescriptor := range pd.InputDescriptors {
		matchedVcJwts, err := selectCredentialsPerInputDescriptor(vcJWTs, inputDescriptor)
		if err != nil {
			return []string{}, err
		}
		if len(matchedVcJwts) == 0 {
			return []string{}, nil
		}
		result = append(result, matchedVcJwts...)

	}

	result = dedupeResult(result)
	return result, nil
}

func dedupeResult(input []string) []string {
	sort.Strings(input)
	var result []string

	for i, item := range input {
		if i == 0 || input[i-1] != item {
			result = append(result, item)
		}
	}
	return result
}

// selectCredentialsPerInputDescriptor selects vcJwts based on the constraints defined in the input descriptor
func selectCredentialsPerInputDescriptor(vcJWTs []string, inputDescriptor InputDescriptor) ([]string, error) {
	answer := make([]string, 0)
	tokenizedField := make([]tokenPath, 0)
	schema := map[string]interface{}{
		"$schema":    "http://json-schema.org/draft-07/schema#",
		"type":       "object",
		"properties": map[string]interface{}{},
		"required":   []string{},
	}

	for _, field := range inputDescriptor.Constraints.Fields {
		token := generateRandomToken()
		tokenizedField = append(tokenizedField, tokenPath{Token: token, Paths: field.Path})

		properties, ok := schema["properties"].(map[string]interface{})
		if !ok {
			return []string{}, errors.New("unable to assert 'properties' type as map[string]interface{}")
		}

		if field.Filter != nil {
			properties[token] = field.Filter
		} else {
			// null is intentionally omitted as a possible type
			anyType := map[string]interface{}{
				"type": []string{"string", "number", "boolean", "object", "array"},
			}
			properties[token] = anyType
		}
		if required, ok := schema["required"].([]string); ok {
			required = append(required, token)
			schema["required"] = required
		}

	}

	for _, vcJWT := range vcJWTs {
		decoded, err := vc.Decode[vc.Claims](vcJWT)
		if err != nil {
			fmt.Println("Error decoding VC:", err)
			continue
		}
		vcJSON := getVcJSON(decoded)

		selectionCandidate := make(map[string]interface{})

		for _, tokenPath := range tokenizedField {
			for _, path := range tokenPath.Paths {
				value, err := jsonpath.Get(path, vcJSON)
				if err != nil {
					fmt.Println("Error getting value from JSON path:", err)
					continue
				}

				selectionCandidate[tokenPath.Token] = value
				break
			}
		}

		validationResult, err := validateWithSchema(schema, selectionCandidate)
		if err != nil {
			return []string{}, fmt.Errorf("error validating schema: %w", err)
		}

		if validationResult.Valid() {
			answer = append(answer, vcJWT)
		}

	}

	return answer, nil

}

func validateWithSchema(schema map[string]interface{}, selectionCandidate map[string]interface{}) (*jsonschema.Result, error) {
	schemaLoader := getSchemaLoader(schema)
	documentLoader := jsonschema.NewGoLoader(selectionCandidate)

	result, err := jsonschema.Validate(schemaLoader, documentLoader)
	return result, err
}

func getSchemaLoader(schema map[string]interface{}) jsonschema.JSONLoader {
	schemaJSON, err := json.Marshal(schema)
	if err != nil {
		fmt.Println("Error marshalling schema:", err)
	}

	schemaLoader := jsonschema.NewStringLoader(string(schemaJSON))
	return schemaLoader
}

func getVcJSON(decoded vc.DecodedVCJWT[vc.Claims]) interface{} {
	marshaledVcJwt, err := json.Marshal(decoded.JWT.Claims)
	if err != nil {
		fmt.Println("Error marshaling VC JWT:", err)
		return interface{}(nil)
	}
	var jsondata interface{}
	err = json.Unmarshal(marshaledVcJwt, &jsondata)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return interface{}(nil)
	}
	return jsondata
}

func generateRandomToken() string {
	b := make([]byte, 16)

	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return hex.EncodeToString(b)
}
