package pexv2_test

import (
	"fmt"
	"testing"

	"github.com/alecthomas/assert/v2"
	testify "github.com/stretchr/testify/assert"
	"github.com/tbd54566975/web5-go"
	"github.com/tbd54566975/web5-go/pexv2"
)

type PresentationInput struct {
	PresentationDefinition pexv2.PresentationDefinition `json:"presentationDefinition"`
	CredentialJwts         []string                     `json:"credentialJwts"`
}

type PresentationOutput struct {
	SelectedCredentials []string `json:"selectedCredentials"`
}

func TestSelectCredentials(t *testing.T) {
	testVectors, err := web5.LoadTestVectors[PresentationInput, PresentationOutput]("../web5-spec/test-vectors/presentation_exchange/select_credentials.json")
	assert.NoError(t, err)

	for _, vector := range testVectors.Vectors {
		t.Run(vector.Description, func(t *testing.T) {
			fmt.Println("Running test vector: ", vector.Description)

			vcJwts, err := pexv2.SelectCredentials(vector.Input.CredentialJwts, vector.Input.PresentationDefinition)

			assert.NoError(t, err)
			testify.ElementsMatch(t, vector.Output.SelectedCredentials, vcJwts)
		})
	}
}
