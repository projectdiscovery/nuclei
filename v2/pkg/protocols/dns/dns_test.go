package dns

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

func TestGenerateDNSVariables(t *testing.T) {
	vars := generateDNSVariables("www.projectdiscovery.io")
	require.Equal(t, map[string]interface{}{
		"FQDN": "www.projectdiscovery.io",
		"RDN":  "projectdiscovery.io",
		"DN":   "projectdiscovery",
		"TLD":  "io",
		"SD":   "www",
	}, vars, "could not get dns variables")
}

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

	req, err := request.Make("one.one.one.one")
	require.Nil(t, err, "could not make dns request")
	require.Equal(t, "one.one.one.one.", req.Question[0].Name, "could not get correct dns question")
}
