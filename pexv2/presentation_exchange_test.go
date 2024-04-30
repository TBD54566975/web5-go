package pexv2_test

import (
	"fmt"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go"
	"github.com/tbd54566975/web5-go/dids/didjwk"
	"github.com/tbd54566975/web5-go/pexv2"
	"github.com/tbd54566975/web5-go/vc"
)

type PresentationInput struct {
	PresentationDefinition pexv2.PresentationDefinition `json:"presentationDefinition"`
	CredentialJwts         []string                     `json:"credentialJwts"`
}

type PresentationOutput struct {
	SelectedCredentials []string `json:"selectedCredentials"`
}

func TestDecode(t *testing.T) {
	testVectors, err := web5.LoadTestVectors[PresentationInput, PresentationOutput]("../web5-spec/test-vectors/presentation_exchange/select_credentials.json")
	assert.NoError(t, err)

	for _, vector := range testVectors.Vectors {
		t.Run(vector.Description, func(t *testing.T) {
			fmt.Println("Running test vector: ", vector.Description)

			vcJwts, err := pexv2.SelectCredentials(vector.Input.CredentialJwts, vector.Input.PresentationDefinition)

			assert.NoError(t, err)
			fmt.Printf("Selected credentials: %s\n\n\n expected output %s\n\n\n", vcJwts, vector.Output.SelectedCredentials)
			assert.Equal(t, vector.Output.SelectedCredentials, vcJwts)

		})
	}

}

func TestDecode_WithArrayFilter(t *testing.T) {
	testVectors, err := web5.LoadTestVectors[PresentationInput, PresentationOutput]("../web5-spec/test-vectors/presentation_exchange/select_credentials_with_filter_array.json")
	assert.NoError(t, err)

	for _, vector := range testVectors.Vectors {
		t.Run(vector.Description, func(t *testing.T) {
			fmt.Println("Running test vector: ", vector.Description)

			vcJwts, err := pexv2.SelectCredentials(vector.Input.CredentialJwts, vector.Input.PresentationDefinition)

			assert.NoError(t, err)
			fmt.Printf("Selected credentials: %s\n\n\n expected output %s\n\n\n", vcJwts, vector.Output.SelectedCredentials)
			assert.Equal(t, vector.Output.SelectedCredentials, vcJwts)

		})
	}

}

func TestDecode_WithConstFilter(t *testing.T) {
	testVectors, err := web5.LoadTestVectors[PresentationInput, PresentationOutput]("../web5-spec/test-vectors/presentation_exchange/select_credentials_with_filter_string.json")
	assert.NoError(t, err)

	for _, vector := range testVectors.Vectors {
		t.Run(vector.Description, func(t *testing.T) {
			fmt.Println("Running test vector: ", vector.Description)

			vcJwts, err := pexv2.SelectCredentials(vector.Input.CredentialJwts, vector.Input.PresentationDefinition)

			assert.NoError(t, err)
			fmt.Printf("Selected credentials: %s\n\n\n expected output %s\n\n\n", vcJwts, vector.Output.SelectedCredentials)
			assert.Equal(t, vector.Output.SelectedCredentials, vcJwts)

		})
	}
}

func TestDecode_WithStringRegexFilter(t *testing.T) {
	testVectors, err := web5.LoadTestVectors[PresentationInput, PresentationOutput]("../web5-spec/test-vectors/presentation_exchange/select_credentials_with_filter_string_pattern.json")
	assert.NoError(t, err)

	for _, vector := range testVectors.Vectors {
		t.Run(vector.Description, func(t *testing.T) {
			fmt.Println("Running test vector: ", vector.Description)

			vcJwts, err := pexv2.SelectCredentials(vector.Input.CredentialJwts, vector.Input.PresentationDefinition)

			assert.NoError(t, err)
			fmt.Printf("Selected credentials: %s\n\n\n expected output %s\n\n\n", vcJwts, vector.Output.SelectedCredentials)
			assert.Equal(t, vector.Output.SelectedCredentials, vcJwts)

		})
	}
}

func TestDecode_WithNumberFilter(t *testing.T) {
	testVectors, err := web5.LoadTestVectors[PresentationInput, PresentationOutput]("../web5-spec/test-vectors/presentation_exchange/select_credentials_with_filter_number.json")
	assert.NoError(t, err)

	for _, vector := range testVectors.Vectors {
		t.Run(vector.Description, func(t *testing.T) {
			fmt.Println("Running test vector: ", vector.Description)

			vcJwts, err := pexv2.SelectCredentials(vector.Input.CredentialJwts, vector.Input.PresentationDefinition)

			assert.NoError(t, err)
			fmt.Printf("Selected credentials: %s\n\n\n expected output %s\n\n\n", vcJwts, vector.Output.SelectedCredentials)
			assert.Equal(t, vector.Output.SelectedCredentials, vcJwts)

		})
	}
}

func TestLol(t *testing.T) {
	subject, err := didjwk.Create()
	if err != nil {
		panic(err)
	}
	// creation
	claims := vc.Claims{"id": subject.URI, "age": 45}
	cred := vc.Create(claims)

	cred.Type = append(cred.Type, "StreetCredential")

	// signing
	vcJWT, err := cred.Sign(subject)
	if err != nil {
		panic(err)
	}

	fmt.Println(vcJWT)
}
