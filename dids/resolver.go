package dids

import (
	"net/http"
	"sync"

	"github.com/tbd54566975/web5-go/dids/didcore"
)

// Resolve resolves the provided DID URI. This function is capable of resolving
// the DID methods implemented in web5-go
func Resolve(uri string) (didcore.ResolutionResult, error) {
	return getDefaultResolver().Resolve(uri)
}

var instance *didResolver
var once sync.Once

func getDefaultResolver() *didResolver {
	once.Do(func() {
		instance = &didResolver{
			resolvers: map[string]DIDResolver{
				"jwk": &JWKResolver{},
				"dht": NewDHTResolver("", http.DefaultClient),
			},
		}
	})

	return instance
}

type DIDResolver interface {
	Resolve(uri string) (didcore.ResolutionResult, error)
}

type didResolver struct {
	resolvers map[string]DIDResolver
}

func (r *didResolver) Resolve(uri string) (didcore.ResolutionResult, error) {
	did, err := Parse(uri)
	if err != nil {
		return didcore.ResolutionResultWithError("invalidDid"), didcore.ResolutionError{Code: "invalidDid"}
	}

	resolver := r.resolvers[did.Method]
	if resolver == nil {
		return didcore.ResolutionResultWithError("methodNotSupported"), didcore.ResolutionError{Code: "methodNotSupported"}
	}

	return resolver.Resolve(uri)
}
