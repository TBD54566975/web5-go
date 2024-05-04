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
		matchedVcJWTs, err := selectCredentialsPerInputDescriptor(vcJWTs, inputDescriptor)
		if err != nil {
			return []string{}, err
		}
		if len(matchedVcJWTs) == 0 {
			return []string{}, nil
		}
		result = append(result, matchedVcJWTs...)

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

func selectCredentialsPerInputDescriptor(vcJWTs []string, inputDescriptor InputDescriptor) ([]string, error) {
	answer := make([]string, 0)
	tokenizedField := make([]tokenPath, 0)
	schema := map[string]any{
		"$schema":    "http://json-schema.org/draft-07/schema#",
		"type":       "object",
		"properties": map[string]any{},
		"required":   []string{},
	}

	for _, field := range inputDescriptor.Constraints.Fields {
		token, err := generateRandomToken()
		if err != nil {
			return []string{}, fmt.Errorf("error generating random token: %w", err)
		}
		tokenizedField = append(tokenizedField, tokenPath{Token: token, Paths: field.Path})

		properties, ok := schema["properties"].(map[string]any)
		if !ok {
			return []string{}, errors.New("unable to assert 'properties' type as map[string]any")
		}

		if field.Filter != nil {
			properties[token] = field.Filter
		} else {
			// null is intentionally omitted as a possible type
			anyType := map[string]any{
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

		selectionCandidate := make(map[string]any)

		for _, tokenPath := range tokenizedField {
			for _, path := range tokenPath.Paths {
				value, err := jsonpath.Get(path, vcJSON)
				if err != nil {
					fmt.Printf("Unable to find value at JSON path: %s. Error: %v\n", path, err)
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

func validateWithSchema(schema map[string]any, selectionCandidate map[string]any) (*jsonschema.Result, error) {
	schemaLoader := getSchemaLoader(schema)
	documentLoader := jsonschema.NewGoLoader(selectionCandidate)

	result, err := jsonschema.Validate(schemaLoader, documentLoader)
	return result, err
}

func getSchemaLoader(schema map[string]any) jsonschema.JSONLoader {
	schemaJSON, err := json.Marshal(schema)
	if err != nil {
		fmt.Println("Error marshalling schema:", err)
	}

	schemaLoader := jsonschema.NewStringLoader(string(schemaJSON))
	return schemaLoader
}

func getVcJSON(decoded vc.DecodedVCJWT[vc.Claims]) any {
	marshaledVcJWT, err := json.Marshal(decoded.JWT.Claims)
	if err != nil {
		fmt.Println("Error marshaling VC JWT:", err)
		return any(nil)
	}
	var jsondata any
	err = json.Unmarshal(marshaledVcJWT, &jsondata)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return any(nil)
	}
	return jsondata
}

func generateRandomToken() (string, error) {
	b := make([]byte, 16)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}
