package http

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v2/internal/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/stretchr/testify/require"
	"go.uber.org/ratelimit"
)

func TestRequest(t *testing.T) {
	err := httpclientpool.Init(&types.Options{})
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
		RateLimiter:  ratelimit.New(100),
	}
	executer := NewExecuter([]*Request{&Request{Path: []string{"{{BaseURL}}"}, Method: "GET", Operators: &operators.Operators{
		Matchers: []*matchers.Matcher{{Type: "dsl", DSL: []string{"!contains(tolower(all_headers), 'x-frame-options')"}, Part: "body"}},
	}}}, protocolOpts)
	err = executer.Compile()
	require.Nil(t, err, "could not compile request")

	_, err = executer.Execute("https://example.com")
	require.Nil(t, err, "could not execute request")

	//	for _, result := range output {
	//		fmt.Printf("%+v\n", result)
	//	}
}
