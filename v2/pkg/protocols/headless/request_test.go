package headless

import (
	"fmt"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/internal/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/headless/engine"
	"github.com/stretchr/testify/require"
)

func TestHeadlessExecuteWithResults(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-headless"
	request := &Request{
		ID: templateID,
		Steps: []*engine.Action{
			{ActionType: "navigate", Data: map[string]string{"url": "{{BaseURL}}"}},
			{ActionType: "waitload"},
		},
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Name:  "test",
				Part:  "data",
				Type:  "word",
				Words: []string{"Example Domain"},
			}},
		},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: map[string]interface{}{"severity": "low", "name": "test"},
	})
	options.Headless = true
	browser, err := engine.New(options)
	require.Nil(t, err, "could not create browser")
	executerOpts.Browser = browser

	err = request.Compile(executerOpts)
	require.Nil(t, err, "could not compile headless request")

	metadata := make(output.InternalEvent)
	previous := make(output.InternalEvent)
	err = request.ExecuteWithResults("https://example.com", metadata, previous, func(event *output.InternalWrappedEvent) {
		for _, result := range event.Results {
			fmt.Printf("Result: %+v\n", result)
		}
	})
	require.Nil(t, err, "could not execute headless request")
}
