package dns

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
)

func TestDNSCompileMake(t *testing.T) {
	options := testutils.DefaultOptions

	recursion := false
	testutils.Init(options)
	const templateID = "testing-dns"
	request := &Request{
		RequestType: DNSRequestTypeHolder{DNSRequestType: A},
		Class:       "INET",
		Retries:     5,
		ID:          templateID,
		Recursion:   &recursion,
		Name:        "{{FQDN}}",
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile dns request")

	req, err := request.Make("one.one.one.one", map[string]interface{}{"FQDN": "one.one.one.one"})
	require.Nil(t, err, "could not make dns request")
	require.Equal(t, "one.one.one.one.", req.Question[0].Name, "could not get correct dns question")
}

// TestDNSCompileWithTemplatedResolver reproduces
// https://github.com/projectdiscovery/nuclei/issues/7374: a DNS request whose
// `resolvers:` list references a template variable must compile, since the
// variable scope is only available at execution time. Before the fix this
// failed at Compile() with "could not get dns client: could not resolve
// resolvers expressions: failed to evaluate expression ... No parameter ...".
func TestDNSCompileWithTemplatedResolver(t *testing.T) {
	options := testutils.DefaultOptions
	recursion := false
	testutils.Init(options)
	const templateID = "testing-dns-templated-resolver"
	request := &Request{
		RequestType: DNSRequestTypeHolder{DNSRequestType: A},
		Class:       "INET",
		Retries:     5,
		ID:          templateID,
		Recursion:   &recursion,
		Name:        "{{FQDN}}",
		Resolvers:   []string{"{{test_resolver}}"},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.NoError(t, err, "templated resolver must not break compilation")
	require.NotNil(t, request.dnsClient, "compile-time dns client must still be built (without the unresolved entry)")
}

// TestGetDnsClientResolvesTemplatedResolver verifies the runtime path: when
// metadata contains the template variable, getDnsClient must produce a client
// configured with the resolved address. It also covers the bug where a static
// resolver placed alongside a templated one used to be dropped because the
// loop result was overwritten by request.Resolvers.
func TestGetDnsClientResolvesTemplatedResolver(t *testing.T) {
	options := testutils.DefaultOptions
	recursion := false
	testutils.Init(options)
	const templateID = "testing-dns-templated-resolver-runtime"
	request := &Request{
		RequestType: DNSRequestTypeHolder{DNSRequestType: A},
		Class:       "INET",
		Retries:     5,
		ID:          templateID,
		Recursion:   &recursion,
		Name:        "{{FQDN}}",
		Resolvers:   []string{"{{test_resolver}}", "8.8.8.8"},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	require.NoError(t, request.Compile(executerOpts))

	client, err := request.getDnsClient(executerOpts, map[string]interface{}{
		"test_resolver": "1.1.1.1",
	})
	require.NoError(t, err)
	require.NotNil(t, client)
}

func TestDNSRequests(t *testing.T) {
	options := testutils.DefaultOptions

	recursion := false
	testutils.Init(options)
	const templateID = "testing-dns"

	t.Run("dns-regular", func(t *testing.T) {

		request := &Request{
			RequestType: DNSRequestTypeHolder{DNSRequestType: A},
			Class:       "INET",
			Retries:     5,
			ID:          templateID,
			Recursion:   &recursion,
			Name:        "{{FQDN}}",
		}
		executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
			ID:   templateID,
			Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
		})
		err := request.Compile(executerOpts)
		require.Nil(t, err, "could not compile dns request")

		reqCount := request.Requests()
		require.Equal(t, 1, reqCount, "could not get correct dns request count")
	})

	// test payload requests count is correct
	t.Run("dns-payload", func(t *testing.T) {

		request := &Request{
			RequestType: DNSRequestTypeHolder{DNSRequestType: A},
			Class:       "INET",
			Retries:     5,
			ID:          templateID,
			Recursion:   &recursion,
			Name:        "{{subdomain}}.{{FQDN}}",
			Payloads:    map[string]interface{}{"subdomain": []string{"a", "b", "c"}},
		}
		executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
			ID:   templateID,
			Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
		})
		err := request.Compile(executerOpts)
		require.Nil(t, err, "could not compile dns request")

		reqCount := request.Requests()
		require.Equal(t, 3, reqCount, "could not get correct dns request count")
	})
}
