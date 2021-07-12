package dns

import (
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/internal/testutils"
	"github.com/stretchr/testify/require"
)

func TestDNSCompileMake(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	const templateID = "testing-dns"
	request := &Request{
		Type:      "A",
		Class:     "INET",
		Retries:   5,
		ID:        templateID,
		Recursion: false,
		Name:      "{{FQDN}}",
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{Severity: goflags.SeverityHolder{Severity: goflags.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile dns request")

	req, err := request.Make("one.one.one.one")
	require.Nil(t, err, "could not make dns request")
	require.Equal(t, "one.one.one.one.", req.Question[0].Name, "could not get correct dns question")
}
