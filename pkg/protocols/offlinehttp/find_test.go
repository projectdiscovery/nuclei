package offlinehttp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	permissionutil "github.com/projectdiscovery/utils/permission"
)

func TestFindResponses(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-offline"
	request := &Request{}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	executerOpts.Operators = []*operators.Operators{{}}
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile file request")

	tempDir, err := os.MkdirTemp("", "test-*")
	require.Nil(t, err, "could not create temporary directory")
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()

	files := map[string]string{
		"test.go":           "TEST",
		"config.txt":        "TEST",
		"final.txt":         "TEST",
		"image_ignored.png": "TEST",
		"test.txt":          "TEST",
	}
	for k, v := range files {
		err = os.WriteFile(filepath.Join(tempDir, k), []byte(v), permissionutil.TempFilePermission)
		require.Nil(t, err, "could not write temporary file")
	}
	expected := []string{"config.txt", "final.txt", "test.txt"}
	got := []string{}
	err = request.getInputPaths(context.Background(), tempDir+"/*", func(item string) error {
		base := filepath.Base(item)
		got = append(got, base)
		return nil
	})
	require.Nil(t, err, "could not get input paths for glob")
	require.ElementsMatch(t, expected, got, "could not get correct file matches for glob")

	got = []string{}
	err = request.getInputPaths(context.Background(), tempDir, func(item string) error {
		base := filepath.Base(item)
		got = append(got, base)
		return nil
	})
	require.Nil(t, err, "could not get input paths for directory")
	require.ElementsMatch(t, expected, got, "could not get correct file matches for directory")
}

func TestGetInputPathsStopsWhenContextCancelled(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)
	request := &Request{}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "testing-offline",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	executerOpts.Operators = []*operators.Operators{{}}
	require.NoError(t, request.Compile(executerOpts))

	tempDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "a.txt"), []byte("TEST"), permissionutil.TempFilePermission))
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "b.txt"), []byte("TEST"), permissionutil.TempFilePermission))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := request.getInputPaths(ctx, tempDir, func(string) error {
		t.Fatal("must not enumerate after cancel")
		return nil
	})
	require.ErrorIs(t, err, context.Canceled)
}
