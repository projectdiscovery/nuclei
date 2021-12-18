package file

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

func TestFileCompile(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-file"
	request := &Request{
		ID:          templateID,
		MaxSize:     1024,
		NoRecursive: false,
		Extensions:  []string{"all", ".lock"},
		DenyList:    []string{".go"},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile file request")

	require.Contains(t, request.denyList, ".go", "could not get .go in denylist")
	require.NotContains(t, request.extensions, ".go", "could get .go in allowlist")
	require.True(t, request.allExtensions, "could not get correct allExtensions")
}
