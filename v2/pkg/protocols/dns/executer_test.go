package dns

import (
	"fmt"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/internal/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/dns/dnsclientpool"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestRequest(t *testing.T) {
	err := dnsclientpool.Init(&types.Options{})
	require.Nil(t, err, "could not initialize dns client pool")

	writer, err := output.NewStandardWriter(true, false, false, "", "")
	require.Nil(t, err, "could not create standard output writer")

	progress, err := progress.NewProgress(false, false, 0)
	require.Nil(t, err, "could not create standard progress writer")

	protocolOpts := &protocols.ExecuterOptions{
		TemplateID:   "testing-dns",
		TemplateInfo: map[string]string{"author": "test"},
		Output:       writer,
		Options:      &types.Options{},
		Progress:     progress,
	}
	req := &Request{Name: "{{FQDN}}", Recursion: true, Class: "inet", Type: "CNAME", Retries: 5, Operators: &operators.Operators{
		Matchers: []*matchers.Matcher{{Type: "word", Words: []string{"github.io"}, Part: "body"}},
	}}
	err = req.Compile(protocolOpts)
	require.Nil(t, err, "could not compile request")

	output, err := req.ExecuteWithResults("docs.hackerone.com.", nil)
	require.Nil(t, err, "could not execute request")

	for _, result := range output {
		fmt.Printf("%+v\n", result)
	}
}

func TestExecuter(t *testing.T) {
	err := dnsclientpool.Init(&types.Options{})
	require.Nil(t, err, "could not initialize dns client pool")

	writer, err := output.NewStandardWriter(true, false, false, "", "")
	require.Nil(t, err, "could not create standard output writer")

	progress, err := progress.NewProgress(false, false, 0)
	require.Nil(t, err, "could not create standard progress writer")

	protocolOpts := &protocols.ExecuterOptions{
		TemplateID:   "testing-dns",
		TemplateInfo: map[string]string{"author": "test"},
		Output:       writer,
		Options:      &types.Options{},
		Progress:     progress,
	}
	executer := NewExecuter([]*Request{&Request{Name: "{{FQDN}}", Recursion: true, Class: "inet", Type: "CNAME", Retries: 5, Operators: &operators.Operators{
		Matchers: []*matchers.Matcher{{Type: "word", Words: []string{"github.io"}, Part: "body"}},
	}}}, protocolOpts)
	err = executer.Compile()
	require.Nil(t, err, "could not compile request")

	_, err = executer.Execute("docs.hackerone.com")
	require.Nil(t, err, "could not execute request")
}
