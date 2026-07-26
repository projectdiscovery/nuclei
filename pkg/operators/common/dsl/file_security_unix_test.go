//go:build unix

package dsl

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestFileHelperDeniesFifo(t *testing.T) {
	_, templatesDir, templatePath := setupFileHelperSandbox(t)
	templateDir := filepath.Dir(templatePath)
	fifoPath := filepath.Join(templateDir, "pipe.fifo")
	require.NoError(t, syscall.Mkfifo(fifoPath, 0o600))

	ctx := &FileLoadContext{
		Options:      &types.Options{},
		TemplatePath: templatePath,
		Catalog:      disk.NewCatalog(templatesDir),
	}

	errCh := make(chan error, 1)
	go func() {
		var evalErr error
		WithFileLoadContext(ctx, func() {
			_, evalErr = evalFile(t, `file("pipe.fifo")`, nil)
		})
		errCh <- evalErr
	}()

	writerCh := make(chan *os.File, 1)
	go func() {
		f, err := os.OpenFile(fifoPath, os.O_WRONLY, 0)
		if err != nil {
			writerCh <- nil
			return
		}
		writerCh <- f
	}()

	timeout := time.After(5 * time.Second)
	var writer *os.File
	select {
	case writer = <-writerCh:
		if writer != nil {
			t.Cleanup(func() { _ = writer.Close() })
		}
	case <-timeout:
		t.Fatal("timed out opening fifo writer")
	}

	select {
	case got := <-errCh:
		require.Error(t, got)
		require.True(t,
			strings.Contains(got.Error(), "not a regular file") ||
				strings.Contains(got.Error(), "could not load") ||
				strings.Contains(got.Error(), "denied") ||
				strings.Contains(got.Error(), "device"),
			got.Error(),
		)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for file() on fifo")
	}
}
