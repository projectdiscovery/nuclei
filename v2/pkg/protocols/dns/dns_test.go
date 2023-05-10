package dns

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
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
