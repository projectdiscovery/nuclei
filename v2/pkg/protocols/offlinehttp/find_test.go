package offlinehttp

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/internal/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/stretchr/testify/require"
)

func TestFindResponses(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-offline"
	request := &Request{}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: map[string]interface{}{"severity": "low", "name": "test"},
	})
	executerOpts.Operators = []*operators.Operators{&operators.Operators{}}
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile file request")

	tempDir, err := ioutil.TempDir("", "test-*")
	require.Nil(t, err, "could not create temporary directory")
	defer os.RemoveAll(tempDir)

	files := map[string]string{
		"test.go":           "TEST",
		"config.txt":        "TEST",
		"final.txt":         "TEST",
		"image_ignored.png": "TEST",
		"test.txt":          "TEST",
	}
	for k, v := range files {
		err = ioutil.WriteFile(path.Join(tempDir, k), []byte(v), 0777)
		require.Nil(t, err, "could not write temporary file")
	}
	expected := []string{"config.txt", "final.txt", "test.txt"}
	got := []string{}
	err = request.getInputPaths(tempDir+"/*", func(item string) {
		base := path.Base(item)
		got = append(got, base)
	})
	require.Nil(t, err, "could not get input paths for glob")
	require.ElementsMatch(t, expected, got, "could not get correct file matches for glob")

	got = []string{}
	err = request.getInputPaths(tempDir, func(item string) {
		base := path.Base(item)
		got = append(got, base)
	})
	require.Nil(t, err, "could not get input paths for directory")
	require.ElementsMatch(t, expected, got, "could not get correct file matches for directory")
}
