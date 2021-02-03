package network

import (
	"encoding/hex"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/internal/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/stretchr/testify/require"
)

func TestNetworkExecuteWithResults(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-network"
	request := &Request{
		ID:       templateID,
		Address:  []string{"{{Hostname}}:80"},
		ReadSize: 2048,
		Inputs:   []*Input{{Data: "GET / HTTP/1.1\r\n\r\n"}},
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Name:  "test",
				Part:  "raw",
				Type:  "word",
				Words: []string{"400 - Bad Request"},
			}},
			Extractors: []*extractors.Extractor{{
				Part:  "raw",
				Type:  "regex",
				Regex: []string{"<h1>.*</h1>"},
			}},
		},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: map[string]interface{}{"severity": "low", "name": "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile network request")

	var finalEvent *output.InternalWrappedEvent
	t.Run("domain-valid", func(t *testing.T) {
		metadata := make(output.InternalEvent)
		previous := make(output.InternalEvent)
		err := request.ExecuteWithResults("example.com", metadata, previous, func(event *output.InternalWrappedEvent) {
			finalEvent = event
		})
		require.Nil(t, err, "could not execute network request")
	})
	require.NotNil(t, finalEvent, "could not get event output from request")
	require.Equal(t, 1, len(finalEvent.Results), "could not get correct number of results")
	require.Equal(t, "test", finalEvent.Results[0].MatcherName, "could not get correct matcher name of results")
	require.Equal(t, 1, len(finalEvent.Results[0].ExtractedResults), "could not get correct number of extracted results")
	require.Equal(t, "<h1>400 - Bad Request</h1>", finalEvent.Results[0].ExtractedResults[0], "could not get correct extracted results")
	finalEvent = nil

	t.Run("invalid-port-override", func(t *testing.T) {
		metadata := make(output.InternalEvent)
		previous := make(output.InternalEvent)
		err := request.ExecuteWithResults("example.com:11211", metadata, previous, func(event *output.InternalWrappedEvent) {
			finalEvent = event
		})
		require.Nil(t, err, "could not execute network request")
	})
	require.NotNil(t, finalEvent, "could not get event output from request")
	require.Equal(t, 1, len(finalEvent.Results), "could not get correct number of results")
	require.Equal(t, "test", finalEvent.Results[0].MatcherName, "could not get correct matcher name of results")
	require.Equal(t, 1, len(finalEvent.Results[0].ExtractedResults), "could not get correct number of extracted results")
	require.Equal(t, "<h1>400 - Bad Request</h1>", finalEvent.Results[0].ExtractedResults[0], "could not get correct extracted results")
	finalEvent = nil

	request.Inputs[0].Type = "hex"
	request.Inputs[0].Data = hex.EncodeToString([]byte("GET / HTTP/1.1\r\n\r\n"))

	t.Run("hex-to-string", func(t *testing.T) {
		metadata := make(output.InternalEvent)
		previous := make(output.InternalEvent)
		err := request.ExecuteWithResults("example.com", metadata, previous, func(event *output.InternalWrappedEvent) {
			finalEvent = event
		})
		require.Nil(t, err, "could not execute network request")
	})
	require.NotNil(t, finalEvent, "could not get event output from request")
	require.Equal(t, 1, len(finalEvent.Results), "could not get correct number of results")
	require.Equal(t, "test", finalEvent.Results[0].MatcherName, "could not get correct matcher name of results")
	require.Equal(t, 1, len(finalEvent.Results[0].ExtractedResults), "could not get correct number of extracted results")
	require.Equal(t, "<h1>400 - Bad Request</h1>", finalEvent.Results[0].ExtractedResults[0], "could not get correct extracted results")
}
