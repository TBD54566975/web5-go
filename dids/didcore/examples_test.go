package didcore_test

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/tbd54566975/web5-go/dids/didcore"
)

// Demonstrates how to unmarshal [Document]'s with mixed types, such as an array of both strings and ordered maps
func ExampleDocument_UnmarshalJSON_contextWithMixedTypes() {
	var doc didcore.Document
	err := json.Unmarshal([]byte(`{
		"@context": [
			"https://www.w3.org/ns/did/v1",
			{ "@base": "did:web:www.linkedin.com" }
		]
	}`), &doc)
	if err != nil {
		panic(err)
	}

	context, ok := doc.Context.([]didcore.Context)
	if !ok {
		panic(errors.New("error unmarshalling Document"))
	}

	fmt.Printf("Document @context array string item: %s\n", context[0])

	orderedMap, ok := context[1].(map[string]interface{})
	if !ok {
		panic(errors.New("error unmarshalling Document"))
	}

	fmt.Printf("Document @context array ordered map item: %s", orderedMap)

	// Output:
	// Document @context array string item: https://www.w3.org/ns/did/v1
	// Document @context array ordered map item: map[@base:did:web:www.linkedin.com]
}
