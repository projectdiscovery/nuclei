package formats

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadLimitedFile(t *testing.T) {
	tmpDir := t.TempDir()
	content := []byte("hello world")
	filePath := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(filePath, content, 0644)
	require.NoError(t, err)

	// Within limit
	data, err := ReadLimitedFile(filePath, int64(len(content)))
	require.NoError(t, err)
	require.Equal(t, content, data)

	// Exceeds limit
	_, err = ReadLimitedFile(filePath, int64(len(content)-1))
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrFileTooLarge))
}

func TestReadLimited(t *testing.T) {
	content := []byte("hello world")

	// Within limit
	data, err := ReadLimited(bytes.NewReader(content), int64(len(content)))
	require.NoError(t, err)
	require.Equal(t, content, data)

	// Exceeds limit
	_, err = ReadLimited(bytes.NewReader(content), int64(len(content)-1))
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrFileTooLarge))
}

func TestReadOpenAPIVarDumpFileOversize(t *testing.T) {
	origFileName := DefaultVarDumpFileName
	origLimit := MaxVarDumpFileSize
	defer func() {
		DefaultVarDumpFileName = origFileName
		MaxVarDumpFileSize = origLimit
	}()

	tmpDir := t.TempDir()
	testDumpFile := filepath.Join(tmpDir, "test_params.yaml")
	DefaultVarDumpFileName = testDumpFile
	MaxVarDumpFileSize = 64

	oversizeContent := strings.Repeat("var:\n  - test=\n", 20)
	err := os.WriteFile(testDumpFile, []byte(oversizeContent), 0644)
	require.NoError(t, err)

	_, err = ReadOpenAPIVarDumpFile()
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrFileTooLarge))
}
