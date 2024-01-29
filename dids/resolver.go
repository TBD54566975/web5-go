package dids

import "sync"

// Resolve resolves the provided DID URI. This function is capable of resolving
// the DID methods implemented in web5-go
func Resolve(uri string) ResolutionResult {
	return getDefaultResolver().resolve(uri)
}

type methodResolver func(did string) ResolutionResult

var instance *didResolver
var once sync.Once

func getDefaultResolver() *didResolver {
	once.Do(func() {
		instance = &didResolver{resolvers: make(map[string]methodResolver)}
		instance.resolvers["jwk"] = ResolveDIDJWK
	})

	return instance
}

type didResolver struct {
	resolvers map[string]methodResolver
}

func (r *didResolver) resolve(uri string) ResolutionResult {
	did, err := Parse(uri)
	if err != nil {
		return ResolutionResultWithError("invalidDid")
	}

	resolver := r.resolvers[did.Method]
	if resolver == nil {
		return ResolutionResultWithError("methodNotSupported")
	}

	return resolver(uri)
}
