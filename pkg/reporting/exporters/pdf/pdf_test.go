package pdf

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewExporter(t *testing.T) {
	options := &Options{File: "test_report.pdf"}
	exporter, err := New(options)
	require.NoError(t, err)
	require.NotNil(t, exporter)
	require.Equal(t, options, exporter.options)
	require.NotNil(t, exporter.data)
}

func TestExportConcurrency(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "nuclei-pdf-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	outputFile := filepath.Join(tempDir, "concurrent_report.pdf")
	options := &Options{File: outputFile}
	exporter, err := New(options)
	require.NoError(t, err)

	var wg sync.WaitGroup
	// Simulate concurrent exports from multiple threads/routines
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			event := &output.ResultEvent{
				TemplateID: fmt.Sprintf("template-%d", id),
				Host:       "example.com",
				Info: model.Info{
					SeverityHolder: severity.Holder{Severity: severity.High},
					Name:           fmt.Sprintf("Test Vulnerability %d", id),
				},
			}
			err := exporter.Export(event)
			assert.NoError(t, err)
		}(i)
	}

	wg.Wait()

	// Verify all events were captured
	require.Len(t, exporter.data, 100)

	// Close and verify file creation
	err = exporter.Close()
	require.NoError(t, err)
	require.FileExists(t, outputFile)
}

func TestExportEmpty(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "nuclei-pdf-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	outputFile := filepath.Join(tempDir, "empty_report.pdf")
	options := &Options{File: outputFile}
	exporter, err := New(options)
	require.NoError(t, err)

	err = exporter.Close()
	require.NoError(t, err)
	require.FileExists(t, outputFile)
}

func TestExportWithVariousSeverities(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "nuclei-pdf-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	outputFile := filepath.Join(tempDir, "severity_report.pdf")
	options := &Options{File: outputFile}
	exporter, err := New(options)
	require.NoError(t, err)

	severities := []severity.Severity{
		severity.Critical,
		severity.High,
		severity.Medium,
		severity.Low,
		severity.Info,
		severity.Unknown,
	}

	for _, sev := range severities {
		event := &output.ResultEvent{
			TemplateID: fmt.Sprintf("template-%s", sev),
			Host:       "example.com",
			Info: model.Info{
				SeverityHolder: severity.Holder{Severity: sev},
				Name:           "Test Vuln",
				Description:    "Test Description",
			},
		}
		err := exporter.Export(event)
		require.NoError(t, err)
	}

	err = exporter.Close()
	require.NoError(t, err)
	require.FileExists(t, outputFile)
}

func TestExportClosed(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "nuclei-pdf-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	outputFile := filepath.Join(tempDir, "closed_test.pdf")
	options := &Options{File: outputFile}
	exporter, err := New(options)
	require.NoError(t, err)

	// Close the exporter
	err = exporter.Close()
	require.NoError(t, err)

	// Verify idempotency of Close
	err = exporter.Close()
	require.NoError(t, err)

	// Verify Export after Close fails
	event := &output.ResultEvent{
		TemplateID: "test",
		Host:       "example.com",
		Info: model.Info{
			SeverityHolder: severity.Holder{Severity: severity.High},
		},
	}
	err = exporter.Export(event)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exporter is closed")
}
