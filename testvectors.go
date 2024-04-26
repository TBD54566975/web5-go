package web5

import (
	"encoding/json"
	"os"
)

// TestVectors are JSON files which are tested against to ensure interop with the specification
type TestVectors[T, U any] struct {
	Description string             `json:"description"`
	Vectors     []TestVector[T, U] `json:"vectors"`
}

// TestVector is an individual test vector case
type TestVector[I, O any] struct {
	Description string `json:"description"`
	Input       I      `json:"input"`
	Output      O      `json:"output"`
	Errors      bool   `json:"errors"`
}

// LoadTestVectors is for reading the vector at the given path
func LoadTestVectors[I, O any](path string) (TestVectors[I, O], error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return TestVectors[I, O]{}, err
	}

	var testVectors TestVectors[I, O]
	err = json.Unmarshal(data, &testVectors)
	if err != nil {
		return TestVectors[I, O]{}, err
	}

	return testVectors, nil
}
