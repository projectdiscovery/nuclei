package file

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	permissionutil "github.com/projectdiscovery/utils/permission"
)

func TestFindInputPaths(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-file"
	request := &Request{
		ID:          templateID,
		MaxSize:     "1Gb",
		NoRecursive: false,
		Extensions:  []string{"all", ".lock"},
		DenyList:    []string{".go"},
		Operators:   newMockOperator(),
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile file request")

	tempDir, err := os.MkdirTemp("", "test-*")
	require.Nil(t, err, "could not create temporary directory")
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()

	files := map[string]string{
		"test.go":           "TEST",
		"config.yaml":       "TEST",
		"final.yaml":        "TEST",
		"image_ignored.png": "TEST",
		"test.js":           "TEST",
	}
	for k, v := range files {
		err = os.WriteFile(filepath.Join(tempDir, k), []byte(v), permissionutil.TempFilePermission)
		require.Nil(t, err, "could not write temporary file")
	}
	expected := []string{"config.yaml", "final.yaml", "test.js"}
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
	request := &Request{
		ID:         "testing-file",
		MaxSize:    "1Gb",
		Extensions: []string{"all"},
		Operators:  newMockOperator(),
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "testing-file",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	require.NoError(t, request.Compile(executerOpts))

	tempDir := t.TempDir()
	for i := 0; i < 20; i++ {
		require.NoError(t, os.WriteFile(filepath.Join(tempDir, fmt.Sprintf("%d.txt", i)), []byte("TEST"), permissionutil.TempFilePermission))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := request.getInputPaths(ctx, tempDir, func(string) error {
		t.Fatal("must not enumerate after cancel")
		return nil
	})
	require.ErrorIs(t, err, context.Canceled)
}

func TestGetInputPathsStopsOnCallbackError(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)
	request := &Request{
		ID:         "testing-file",
		MaxSize:    "1Gb",
		Extensions: []string{"all"},
		Operators:  newMockOperator(),
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   "testing-file",
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	require.NoError(t, request.Compile(executerOpts))

	tempDir := t.TempDir()
	for i := 0; i < 20; i++ {
		require.NoError(t, os.WriteFile(filepath.Join(tempDir, fmt.Sprintf("%d.txt", i)), []byte("TEST"), permissionutil.TempFilePermission))
	}

	seen := 0
	err := request.getInputPaths(context.Background(), tempDir, func(string) error {
		seen++
		return context.Canceled
	})
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, seen)
}
