package file

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	permissionutil "github.com/projectdiscovery/utils/permission"
)

func TestFileExecuteWithResults(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-file"
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	request := &Request{
		ID:          templateID,
		MaxSize:     "1Gb",
		NoRecursive: false,
		Extensions:  []string{"all"},
		DenyList:    []string{".go"},
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Name:  "test",
				Part:  "raw",
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"1.1.1.1"},
			}},
			Extractors: []*extractors.Extractor{{
				Part:  "raw",
				Type:  extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor},
				Regex: []string{"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+"},
			}},
		},
		options: executerOpts,
	}
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile file request")

	tempDir, err := os.MkdirTemp("", "test-*")
	require.Nil(t, err, "could not create temporary directory")
	defer os.RemoveAll(tempDir)

	files := map[string]string{
		"config.yaml": "TEST\r\n1.1.1.1\r\n",
	}
	for k, v := range files {
		err = os.WriteFile(filepath.Join(tempDir, k), []byte(v), permissionutil.TempFilePermission)
		require.Nil(t, err, "could not write temporary file")
	}

	var finalEvent *output.InternalWrappedEvent
	t.Run("valid", func(t *testing.T) {
		metadata := make(output.InternalEvent)
		previous := make(output.InternalEvent)
		ctxArgs := contextargs.NewWithInput(tempDir)
		err := request.ExecuteWithResults(ctxArgs, metadata, previous, func(event *output.InternalWrappedEvent) {
			finalEvent = event
		})
		require.Nil(t, err, "could not execute file request")
	})
	require.NotNil(t, finalEvent, "could not get event output from request")
	require.Equal(t, 1, len(finalEvent.Results), "could not get correct number of results")
	require.Equal(t, "test", finalEvent.Results[0].MatcherName, "could not get correct matcher name of results")
	require.Equal(t, 1, len(finalEvent.Results[0].ExtractedResults), "could not get correct number of extracted results")
	require.Equal(t, "1.1.1.1", finalEvent.Results[0].ExtractedResults[0], "could not get correct extracted results")
	finalEvent = nil
}
