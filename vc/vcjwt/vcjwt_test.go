package vcjwt_test

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/vc"
	"github.com/tbd54566975/web5-go/vc/vcjwt"
)

type vector struct {
	description string
	input       string
	errors      bool
}

func TestDecode(t *testing.T) {
	// TODO: move these to web5-spec repo test-vectors (Moe - 2024-02-24)
	vectors := []vector{
		{
			description: "fail to decode jwt",
			input:       "doodoo",
			errors:      true,
		},
		{
			description: "no claims",
			input:       "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpqd2s6ZXlKcmRIa2lPaUpQUzFBaUxDSmpjbllpT2lKRlpESTFOVEU1SWl3aWVDSTZJa3RPTVZGRU5ETkhZVkpJTm1OeWJpMTFTWFk0ZDBoT1pqZHlSMlkyVUY5RFMxZzJkbmsyTUdjMWQyc2lmUSMwIn0.e30.1iq9_pDtMlzL22h6xVY77nRNfXnR3oFU2kNYDAM52dPAs0l8zLL6AJ18B8rz9HziYzRo4Zo_jyYhq4nlHE3lBw",
			errors:      true,
		}, {
			description: "no vc claim",
			input:       "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpqd2s6ZXlKcmRIa2lPaUpQUzFBaUxDSmpjbllpT2lKRlpESTFOVEU1SWl3aWVDSTZJa0YyZFMxVVNsTlRWakZKT0dob1NrUmFlWGw1YUhnMmVHSlZjamRQT0RWMWRFMWpaa3RLVDJOblFWVWlmUSMwIn0.eyJoZWhlIjoiaGkifQ.QQ5aottVrsHRisxx7vRzin9CnyOcxeScxLOIy5qI30pV2FkXXBe3BdyujLS7i7M0CHW0eS9XhaVKe76504RZCQ",
			errors:      true,
		}, {
			description: "vc claim wrong type",
			input:       "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpqd2s6ZXlKcmRIa2lPaUpQUzFBaUxDSmpjbllpT2lKRlpESTFOVEU1SWl3aWVDSTZJbEZvUkhsdFprdzFaQzB0WjFGQ1prOVNOMlZFYjBrelprTjJOVUV0Y3pBMGFYZHlZMGRsTkVWd1lsa2lmUSMwIn0.eyJ2YyI6ImhpIn0.O_-xPUAZhi9W3OD1pJn4wN5Q9nZKYXcmtJPhWuk6WxlOXMca2jNXyjYpEKCJ1vFWZ4OHfSifErPvClLsH8-MCQ",
			errors:      true,
		}, {
			description: "legit",
			input:       "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpqd2s6ZXlKcmRIa2lPaUpQUzFBaUxDSmpjbllpT2lKRlpESTFOVEU1SWl3aWVDSTZJbVJwVGkxRlEydGhaRTVEVlVKZlUxRkhTVFJtVUdOZlluVmZObmt3VWpKRFdEUllkMjlTUzBjNFVEZ2lmUSMwIn0.eyJpc3MiOiJkaWQ6andrOmV5SnJkSGtpT2lKUFMxQWlMQ0pqY25ZaU9pSkZaREkxTlRFNUlpd2llQ0k2SW1ScFRpMUZRMnRoWkU1RFZVSmZVMUZIU1RSbVVHTmZZblZmTm5rd1VqSkRXRFJZZDI5U1MwYzRVRGdpZlEiLCJqdGkiOiJ1cm46dmM6dXVpZDoxOGQ5OTZjZi03N2YwLTRkYjgtOGQ5MS0zNGI1ZDY1NzcwNmUiLCJuYmYiOjE3MDg3NTY3ODUsInN1YiI6ImRpZDpqd2s6ZXlKcmRIa2lPaUpQUzFBaUxDSmpjbllpT2lKRlpESTFOVEU1SWl3aWVDSTZJbVJwVGkxRlEydGhaRTVEVlVKZlUxRkhTVFJtVUdOZlluVmZObmt3VWpKRFdEUllkMjlTUzBjNFVEZ2lmUSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiZGlkOmp3azpleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkltUnBUaTFGUTJ0aFpFNURWVUpmVTFGSFNUUm1VR05mWW5WZk5ua3dVakpEV0RSWWQyOVNTMGM0VURnaWZRIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6andrOmV5SnJkSGtpT2lKUFMxQWlMQ0pqY25ZaU9pSkZaREkxTlRFNUlpd2llQ0k2SW1ScFRpMUZRMnRoWkU1RFZVSmZVMUZIU1RSbVVHTmZZblZmTm5rd1VqSkRXRFJZZDI5U1MwYzRVRGdpZlEifSwiaWQiOiJ1cm46dmM6dXVpZDoxOGQ5OTZjZi03N2YwLTRkYjgtOGQ5MS0zNGI1ZDY1NzcwNmUiLCJpc3N1YW5jZURhdGUiOiIyMDI0LTAyLTI0VDA2OjM5OjQ1WiJ9fQ.Y1-9dFop7bg_0jvgZMLyE3CPjnSXH9SGTHeA_jn5HosYbhST8y_pK7LcDeCYLSgDfiIOeVsvJFqOr3XT2J2cDA",
			errors:      false,
		},
	}

	for _, tt := range vectors {
		t.Run(tt.description, func(t *testing.T) {
			decoded, err := vcjwt.Decode[vc.Claims](tt.input)

			if tt.errors == true {
				assert.Error(t, err)
				assert.Equal(t, vcjwt.Decoded[vc.Claims]{}, decoded)
			} else {
				assert.NoError(t, err)
				assert.NotEqual(t, vcjwt.Decoded[vc.Claims]{}, decoded)
			}
		})
	}
}
