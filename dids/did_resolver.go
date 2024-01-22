package dids

import "sync"

type DIDMethodResolver func(didURI string) ResolutionResult

type didResolver struct {
	resolvers map[string]DIDMethodResolver
}

func (r *didResolver) RegisterDIDMethodResolver(method string, resolver DIDMethodResolver) {
	r.resolvers[method] = resolver
}

func (r *didResolver) Resolve(uri string) ResolutionResult {
	didURI, err := ParseURI(uri)
	if err != nil {
		return ResolutionResultWithError("invalidDid")
	}

	resolver := r.resolvers[didURI.Method]
	if resolver == nil {
		return ResolutionResultWithError("methodNotSupported")
	}

	return resolver(uri)
}

var instance *didResolver
var once sync.Once

func GetDefaultResolver() *didResolver {
	once.Do(func() {
		instance = &didResolver{resolvers: make(map[string]DIDMethodResolver)}
		instance.RegisterDIDMethodResolver("jwk", ResolveDIDJWK)
	})

	return instance
}
