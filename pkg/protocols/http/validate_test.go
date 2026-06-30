package http

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
)

func TestValidateRedirectsCombinations(t *testing.T) {
	t.Run("redirects and host-redirects conflict", func(t *testing.T) {
		req := &Request{Redirects: true, HostRedirects: true}
		err := req.validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "'redirects' and 'host-redirects' can't be used together")
	})

	t.Run("redirects alone is valid", func(t *testing.T) {
		req := &Request{Redirects: true}
		err := req.validate()
		require.NoError(t, err)
	})

	t.Run("host-redirects alone is valid", func(t *testing.T) {
		req := &Request{HostRedirects: true}
		err := req.validate()
		require.NoError(t, err)
	})

	t.Run("protocol-redirects without redirects or host-redirects is invalid", func(t *testing.T) {
		req := &Request{ProtocolRedirects: true}
		err := req.validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "'protocol-redirects' requires 'redirects' or 'host-redirects'")
	})

	t.Run("protocol-redirects with redirects is valid", func(t *testing.T) {
		req := &Request{Redirects: true, ProtocolRedirects: true}
		err := req.validate()
		require.NoError(t, err)
	})

	t.Run("protocol-redirects with host-redirects is valid", func(t *testing.T) {
		req := &Request{HostRedirects: true, ProtocolRedirects: true}
		err := req.validate()
		require.NoError(t, err)
	})

	t.Run("no redirect options is valid", func(t *testing.T) {
		req := &Request{}
		err := req.validate()
		require.NoError(t, err)
	})
}

func TestValidateFuzzingWithRequestCondition(t *testing.T) {
	t.Run("matcher dsl", func(t *testing.T) {
		req := &Request{
			Fuzzing: []*fuzz.Rule{{}},
			Operators: operators.Operators{
				Matchers: []*matchers.Matcher{
					{DSL: []string{"duration_1 > 18"}},
				},
			},
		}
		err := req.validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "'fuzzing' and 'request-condition' can't be used together")
	})

	t.Run("extractor part", func(t *testing.T) {
		req := &Request{
			Fuzzing: []*fuzz.Rule{{}},
			Operators: operators.Operators{
				Extractors: []*extractors.Extractor{
					{Part: "body_1"},
				},
			},
		}
		err := req.validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "'fuzzing' and 'request-condition' can't be used together")
	})
}
