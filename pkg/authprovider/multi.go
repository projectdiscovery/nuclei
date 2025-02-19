package authprovider

import (
	"net/url"

	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	urlutil "github.com/projectdiscovery/utils/url"
)

// MultiAuthProvider is a convenience wrapper for multiple auth providers
// it returns the first matching auth strategy for a given domain
// if there are multiple auth strategies for a given domain, it returns the first one
type MultiAuthProvider struct {
	Providers []AuthProvider
}

// NewMultiAuthProvider creates a new multi auth provider
func NewMultiAuthProvider(providers ...AuthProvider) AuthProvider {
	return &MultiAuthProvider{Providers: providers}
}

func (m *MultiAuthProvider) LookupAddr(host string) []authx.AuthStrategy {
	for _, provider := range m.Providers {
		strategy := provider.LookupAddr(host)
		if len(strategy) > 0 {
			return strategy
		}
	}
	return nil
}

func (m *MultiAuthProvider) LookupURL(u *url.URL) []authx.AuthStrategy {
	for _, provider := range m.Providers {
		strategy := provider.LookupURL(u)
		if strategy != nil {
			return strategy
		}
	}
	return nil
}

func (m *MultiAuthProvider) LookupURLX(u *urlutil.URL) []authx.AuthStrategy {
	for _, provider := range m.Providers {
		strategy := provider.LookupURLX(u)
		if strategy != nil {
			return strategy
		}
	}
	return nil
}

func (m *MultiAuthProvider) GetTemplatePaths() []string {
	var res []string
	for _, provider := range m.Providers {
		res = append(res, provider.GetTemplatePaths()...)
	}
	return res
}

func (m *MultiAuthProvider) PreFetchSecrets() error {
	for _, provider := range m.Providers {
		if err := provider.PreFetchSecrets(); err != nil {
			return err
		}
	}
	return nil
}
