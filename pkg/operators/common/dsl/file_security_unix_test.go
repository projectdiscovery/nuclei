//go:build unix

package dsl

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestFileHelperDeniesFifo(t *testing.T) {
	_, templatesDir, templatePath := setupFileHelperSandbox(t)
	templateDir := filepath.Dir(templatePath)
	fifoPath := filepath.Join(templateDir, "pipe.fifo")
	require.NoError(t, syscall.Mkfifo(fifoPath, 0o600))

	// Hold an RDWR handle so the helper's read open does not block waiting for a
	// writer, and so rejection does not depend on a separate O_WRONLY opener.
	keepalive, err := os.OpenFile(fifoPath, os.O_RDWR, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = keepalive.Close() })

	ctx := &FileLoadContext{
		Options:      &types.Options{},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	var got error
	WithFileLoadContext(ctx, func() {
		_, got = evalFile(t, `file("pipe.fifo")`, nil)
	})
	require.Error(t, got)
	require.Contains(t, got.Error(), "not a regular file")
}
