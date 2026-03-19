package runner

import (
	"errors"
	"net/url"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	httpProtocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/stretchr/testify/require"
)

type testAuthProvider struct {
	calls int
	err   error
}

func (t *testAuthProvider) LookupAddr(string) []authx.AuthStrategy {
	return nil
}

func (t *testAuthProvider) LookupURL(*url.URL) []authx.AuthStrategy {
	return nil
}

func (t *testAuthProvider) LookupURLX(*urlutil.URL) []authx.AuthStrategy {
	return nil
}

func (t *testAuthProvider) GetTemplatePaths() []string {
	return nil
}

func (t *testAuthProvider) PreFetchSecrets() error {
	t.calls++
	return t.err
}

func TestPreFetchAuthSecrets(t *testing.T) {
	require.NoError(t, PreFetchAuthSecrets(nil))

	provider := &testAuthProvider{}
	require.NoError(t, PreFetchAuthSecrets(provider))
	require.Equal(t, 1, provider.calls)
}

func TestPreFetchAuthSecretsReturnsProviderError(t *testing.T) {
	expectedErr := errors.New("prefetch failed")
	provider := &testAuthProvider{err: expectedErr}

	require.ErrorIs(t, PreFetchAuthSecrets(provider), expectedErr)
	require.Equal(t, 1, provider.calls)
}

func TestPrepareAuthTemplateSkipsSecretFile(t *testing.T) {
	tmpl := &templates.Template{
		RequestsHTTP: []*httpProtocol.Request{{}, {}},
	}

	prepareAuthTemplate(tmpl)

	for _, request := range tmpl.RequestsHTTP {
		require.True(t, request.SkipSecretFile)
	}
}

func TestPrepareAuthTemplateSkipsSecretFileForEachInstance(t *testing.T) {
	templatesToPrepare := []*templates.Template{
		{RequestsHTTP: []*httpProtocol.Request{{}}},
		{RequestsHTTP: []*httpProtocol.Request{{}}},
	}

	for _, tmpl := range templatesToPrepare {
		prepareAuthTemplate(tmpl)
		for _, request := range tmpl.RequestsHTTP {
			require.True(t, request.SkipSecretFile)
		}
	}
}
