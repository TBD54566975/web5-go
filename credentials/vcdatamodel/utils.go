package vcdatamodel

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// This function will marshal a struct, and then unmarshal it into a map to add
// any additional misc fields that are not automatically included (via json tags)
// before unmarshaling the map as the final return value.
// Typically this should be used on any struct which contains a dynamic number of unknown
// fields at runtime. The fields should be added back when marshaling, and this function
// will accomplish that behavior.
func marshalMisc(data interface{}, misc *map[string]interface{}) ([]byte, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	var combined map[string]interface{}
	err = json.Unmarshal(bytes, &combined)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal misc additional fields: %w", err)
	}

	// Add unknown fields to the map
	for key, value := range *misc {
		combined[key] = value
	}

	return json.Marshal(combined)
}

// get rid of any possible leading characters
func trimJSON(data []byte) []byte {
	return bytes.TrimLeft(data, " \t\r\n")
}

func isJSONArray(data []byte) bool {
	x := trimJSON(data)
	return len(x) > 0 && x[0] == '['
}

func isJSONObj(data []byte) bool {
	x := trimJSON(data)
	return len(x) > 0 && x[0] == '{'
}
