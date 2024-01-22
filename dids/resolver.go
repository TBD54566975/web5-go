package dids

import "sync"

type MethodResolver func(did string) ResolutionResult

type didResolver struct {
	resolvers map[string]MethodResolver
}

func (r *didResolver) RegisterMethodResolver(method string, resolver MethodResolver) {
	r.resolvers[method] = resolver
}

func (r *didResolver) Resolve(uri string) ResolutionResult {
	did, err := ParseURI(uri)
	if err != nil {
		return ResolutionResultWithError("invalidDid")
	}

	resolver := r.resolvers[did.Method]
	if resolver == nil {
		return ResolutionResultWithError("methodNotSupported")
	}

	return resolver(uri)
}

var instance *didResolver
var once sync.Once

func GetDefaultResolver() *didResolver {
	once.Do(func() {
		instance = &didResolver{resolvers: make(map[string]MethodResolver)}
		instance.RegisterMethodResolver("jwk", ResolveDIDJWK)
	})

	return instance
}
