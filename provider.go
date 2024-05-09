package gooauth

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

type ProviderType string

const (
	PROVIDER_WECHAT ProviderType = "wechat"
)

// Provider needs to be implemented for each 3rd party authentication provider
// e.g. Facebook, Twitter, etc...
type Provider interface {
	ProviderType() ProviderType
	GetAuthorizeURL(state string) string
	FetchToken(code string) (*oauth2.Token, string, error)
	FetchUser(token *oauth2.Token, openid string) (User, error)
}

// Providers is list of known/available providers.
type Providers map[ProviderType]Provider

var providers = Providers{}

// UseProviders adds a list of available providers for use with Goth.
// Can be called multiple times. If you pass the same provider more
// than once, the last will be used.
func UseProviders(viders ...Provider) {
	for _, provider := range viders {
		providers[provider.ProviderType()] = provider
	}
}

// GetProviders returns a list of all the providers currently in use.
func GetProviders() Providers {
	return providers
}

// GetProvider returns a previously created provider. If Goth has not
// been told to use the named provider it will return an error.
func GetProvider(pType ProviderType) (Provider, error) {
	provider := providers[pType]
	if provider == nil {
		return nil, fmt.Errorf("no provider for %s exists", pType)
	}
	return provider, nil
}

// ClearProviders will remove all providers currently in use.
// This is useful, mostly, for testing purposes.
func ClearProviders() {
	providers = Providers{}
}

// ContextForClient provides a context for use with oauth2.
func ContextForClient(h *http.Client) context.Context {
	if h == nil {
		return context.TODO()
	}
	return context.WithValue(context.TODO(), oauth2.HTTPClient, h)
}

// HTTPClientWithFallBack to be used in all fetch operations.
func HTTPClientWithFallBack(h *http.Client) *http.Client {
	if h != nil {
		return h
	}
	return http.DefaultClient
}
