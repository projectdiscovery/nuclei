package file

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	permissionutil "github.com/projectdiscovery/utils/permission"
)

func zipFile(t *testing.T, fileName string, data []byte) []byte {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	w1, err := w.Create(fileName)
	require.NoError(t, err)
	_, err = w1.Write(data)
	require.NoError(t, err)
	err = w.Close()
	require.NoError(t, err)
	return b.Bytes()
}

func gzipFile(t *testing.T, data []byte) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, err := w.Write(data)
	require.NoError(t, err)
	err = w.Close()
	require.NoError(t, err)
	return b.Bytes()
}

func TestFileExecuteWithResults(t *testing.T) {
	var testCaseBase = []byte("TEST\r\n1.1.1.1\r\n")
	const testCaseBaseFilename = "config.yaml"
	var testCases = []struct {
		fileName string
		data     []byte
	}{
		{
			fileName: testCaseBaseFilename,
			data:     testCaseBase,
		},
		{
			fileName: testCaseBaseFilename + ".gz",
			data:     gzipFile(t, testCaseBase),
		},
		{
			fileName: "config.yaml.zip",
			data:     zipFile(t, testCaseBaseFilename, testCaseBase),
		},
	}

	for _, tt := range testCases {
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
			Archive:     true,
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

		files := map[string][]byte{
			tt.fileName: tt.data,
		}
		for k, v := range files {
			err = os.WriteFile(filepath.Join(tempDir, k), v, permissionutil.TempFilePermission)
			require.Nil(t, err, "could not write temporary file")
		}

		var finalEvent *output.InternalWrappedEvent
		t.Run("valid", func(t *testing.T) {
			metadata := make(output.InternalEvent)
			previous := make(output.InternalEvent)
			ctxArgs := contextargs.NewWithInput(context.Background(), tempDir)
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
}
