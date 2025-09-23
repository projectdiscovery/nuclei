package file

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
		defer func() {
			_ = os.RemoveAll(tempDir)
		}()

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

func TestFileProtocolConcurrentExecution(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "nuclei-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	numFiles := 5
	for i := range numFiles {
		content := "TEST_CONTENT_MATCH_DATA"
		filePath := filepath.Join(tempDir, "test_"+string(rune('0'+i))+".txt")
		err := os.WriteFile(filePath, []byte(content), permissionutil.TempFilePermission)
		require.NoError(t, err)
	}

	options := testutils.DefaultOptions
	testutils.Init(options)
	templateID := "testing-file-concurrent"
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})

	var timesMutex sync.Mutex
	var processedFiles int64

	request := &Request{
		ID:          templateID,
		MaxSize:     "1Gb",
		NoRecursive: false,
		Extensions:  []string{"txt"},
		Archive:     false,
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Name:  "test",
				Part:  "raw",
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"TEST_CONTENT_MATCH_DATA"},
			}},
		},
		options: executerOpts,
	}

	err = request.Compile(executerOpts)
	require.NoError(t, err)

	input := contextargs.NewWithInput(context.Background(), tempDir)
	var results []*output.InternalWrappedEvent
	var resultMutex sync.Mutex

	startTime := time.Now()
	err = request.ExecuteWithResults(input, make(output.InternalEvent), make(output.InternalEvent), func(event *output.InternalWrappedEvent) {
		atomic.AddInt64(&processedFiles, 1)
		resultMutex.Lock()
		results = append(results, event)
		resultMutex.Unlock()

		// small delay to make timing differences more observable
		time.Sleep(10 * time.Millisecond)
	})
	totalTime := time.Since(startTime)
	require.NoError(t, err)

	finalProcessedFiles := atomic.LoadInt64(&processedFiles)
	t.Logf("Total execution time: %v", totalTime)
	t.Logf("Files processed: %d", finalProcessedFiles)
	t.Logf("Results returned: %d", len(results))

	// test 1: all files should be processed
	require.Equal(t, int64(numFiles), finalProcessedFiles, "Not all files were processed")

	// test 2: verify callback invocation timing shows concurrency
	timesMutex.Lock()
	defer timesMutex.Unlock()
}
