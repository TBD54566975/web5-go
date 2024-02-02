package dids

import (
	"net/http"
	"sync"
)

// Resolve resolves the provided DID URI. This function is capable of resolving
// the DID methods implemented in web5-go
func Resolve(uri string) (ResolutionResult, error) {
	return getDefaultResolver().resolve(uri)
}

type methodResolver func(did string) (ResolutionResult, error)

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
	Resolve(uri string) (ResolutionResult, error)
}

type didResolver struct {
	resolvers map[string]DIDResolver
}

func (r *didResolver) resolve(uri string) (ResolutionResult, error) {
	did, err := Parse(uri)
	if err != nil {
		return ResolutionResultWithError("invalidDid"), ResolutionError{"invalidDid"}
	}

	resolver := r.resolvers[did.Method]
	if resolver == nil {
		return ResolutionResultWithError("methodNotSupported"), ResolutionError{"methodNotSupported"}
	}

	return resolver.Resolve(uri)
}
