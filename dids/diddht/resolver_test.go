package diddht

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/tbd54566975/web5-go/dids/didcore"
)

const dhtSpecVectors string = "../../web5-spec/test-vectors/did_dht/resolve.json"

type vector struct {
	Description string `json:"description"`
	Input       struct {
		DIDUri string `json:"didUri"`
	} `json:"input"`
	Output struct {
		Document              didcore.Document `json:"document"`
		DIDResolutionMetadata struct {
			Error string `json:"error"`
		} `json:"didResolutionMetadata"`
	} `json:"output"`
	Errors bool `json:"errors"`
}

func initVector() ([]vector, error) {
	// Load test vectors from file
	data, err := os.ReadFile(dhtSpecVectors)
	if err != nil {
		return nil, err
	}

	// Unmarshal test vectors
	vectorData := struct {
		Vectors []vector `json:"vectors"`
	}{}
	if err := json.Unmarshal(data, &vectorData); err != nil {
		return nil, err
	}
	return vectorData.Vectors, nil
}

func Test_VectorsResolve(t *testing.T) {
	vectors, err := initVector()
	assert.NoError(t, err)

	mocks := map[string]vector{}
	for _, v := range vectors {
		mocks[v.Input.DIDUri] = v
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		return
	}))
	defer ts.Close()

	r := NewResolver(ts.URL, http.DefaultClient)

	for _, vector := range vectors {
		t.Run(vector.Description, func(t *testing.T) {
			if vector.Errors {
				res, err := r.Resolve(vector.Input.DIDUri)
				assert.True(t, err != nil)
				assert.Equal(t, res.ResolutionMetadata.Error, vector.Output.DIDResolutionMetadata.Error)
			} else {
				r = DefaultResolver()
				res, err := r.Resolve(vector.Input.DIDUri)
				assert.NoError(t, err)
				print, err := json.MarshalIndent(res.Document, "", "  ")
				assert.NoError(t, err)

				fmt.Printf("RESP: %s\n", print)
				assert.Equal(t, res.Document, vector.Output.Document)
			}
		})
	}
}

func Test_resolve(t *testing.T) {

	// vector taken from https://github.com/TBD54566975/web5-js/blob/91d52aaa9410db5e5f7c3c31ebfe0d4956028496/packages/dids/tests/methods/did-dht.spec.ts#L725
	vectors := map[string]string{
		"did:dht:9tjoow45ef1hksoo96bmzkwwy3mhme95d7fsi3ezjyjghmp75qyo": "ea33e704f3a48a3392f54b28744cdfb4e24780699f92ba7df62fd486d2a2cda3f263e1c6bcbd" +
			"75d438be7316e5d6e94b13e98151f599cfecefad0b37432bd90a0000000065b0ed1600008400" +
			"0000000300000000035f6b30045f6469643439746a6f6f773435656631686b736f6f3936626d" +
			"7a6b777779336d686d653935643766736933657a6a796a67686d70373571796f000010000100" +
			"001c2000373669643d303b743d303b6b3d5f464d49553174425a63566145502d437536715542" +
			"6c66466f5f73665332726c4630675362693239323445045f747970045f6469643439746a6f6f" +
			"773435656631686b736f6f3936626d7a6b777779336d686d653935643766736933657a6a796a" +
			"67686d70373571796f000010000100001c2000070669643d372c36045f6469643439746a6f6f" +
			"773435656631686b736f6f3936626d7a6b777779336d686d653935643766736933657a6a796a" +
			"67686d70373571796f000010000100001c20002726763d303b766d3d6b303b617574683d6b30" +
			"3b61736d3d6b303b64656c3d6b303b696e763d6b30",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		did := "did:dht:" + r.URL.Path[1:]
		defer r.Body.Close()
		buf, ok := vectors[did]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		data, err := hex.DecodeString(buf)
		assert.NoError(t, err)
		_, err = w.Write(data)
		assert.NoError(t, err)

	}))
	defer ts.Close()

	r := NewResolver(ts.URL, http.DefaultClient)

	for did := range vectors {
		t.Run(did, func(t *testing.T) {
			res, err := r.Resolve(did)
			assert.NoError(t, err)
			assert.NotZero(t, res.Document)
			assert.Equal(t, res.Document.ID, did)
		})
	}
}
