package file

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v2/internal/testutils"
	"github.com/stretchr/testify/require"
)

func TestFileCompile(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-file"
	request := &Request{
		ID:                templateID,
		MaxSize:           1024,
		NoRecursive:       false,
		Extensions:        []string{"all", ".lock"},
		ExtensionDenylist: []string{".go"},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: map[string]interface{}{"severity": "low", "name": "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile file request")

	require.Contains(t, request.extensionDenylist, ".go", "could not get .go in denylist")
	require.NotContains(t, request.extensions, ".go", "could get .go in allowlist")
	require.True(t, request.allExtensions, "could not get correct allExtensions")
}
