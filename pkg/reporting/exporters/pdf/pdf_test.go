package pdf

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

func createMockResultEvent(sev severity.Severity, templateID, host string) *output.ResultEvent {
	return &output.ResultEvent{
		TemplateID: templateID,
		Host:       host,
		Matched:    host + "/matched",
		Timestamp:  time.Now(),
		Info: model.Info{
			Name:           "Test Vulnerability " + templateID,
			Description:    "This is a test vulnerability description for " + templateID,
			SeverityHolder: severity.Holder{Severity: sev},
		},
	}
}

func TestNew(t *testing.T) {
	options := &Options{File: "/tmp/test.pdf"}
	exporter, err := New(options)
	require.NoError(t, err)
	require.NotNil(t, exporter)
	require.NotNil(t, exporter.options)
	require.NotNil(t, exporter.mutex)
	require.NotNil(t, exporter.results)
	require.Equal(t, 0, len(exporter.results))
}

func TestExport_AccumulatesResults(t *testing.T) {
	options := &Options{File: "/tmp/test.pdf"}
	exporter, err := New(options)
	require.NoError(t, err)

	event1 := createMockResultEvent(severity.High, "CVE-2021-1234", "example.com")
	event2 := createMockResultEvent(severity.Critical, "CVE-2021-5678", "test.com")
	event3 := createMockResultEvent(severity.Low, "CVE-2021-9999", "demo.com")

	require.NoError(t, exporter.Export(event1))
	require.NoError(t, exporter.Export(event2))
	require.NoError(t, exporter.Export(event3))

	require.Equal(t, 3, len(exporter.results))
}

func TestExport_NilEvent(t *testing.T) {
	options := &Options{File: "/tmp/test.pdf"}
	exporter, err := New(options)
	require.NoError(t, err)

	err = exporter.Export(nil)
	require.NoError(t, err)
	require.Equal(t, 0, len(exporter.results))
}

func TestExport_ThreadSafety(t *testing.T) {
	options := &Options{File: "/tmp/test.pdf"}
	exporter, err := New(options)
	require.NoError(t, err)

	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			event := createMockResultEvent(severity.Medium, "CVE-TEST", "host.com")
			_ = exporter.Export(event)
		}(i)
	}

	wg.Wait()
	require.Equal(t, numGoroutines, len(exporter.results))
}

func TestClose_GeneratesValidPDF(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "nuclei-test-*.pdf")
	require.NoError(t, err)
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer func() { _ = os.Remove(tmpPath) }()

	options := &Options{File: tmpPath}
	exporter, err := New(options)
	require.NoError(t, err)

	event := createMockResultEvent(severity.High, "CVE-2021-1234", "example.com")
	require.NoError(t, exporter.Export(event))
	require.NoError(t, exporter.Close())

	fileInfo, err := os.Stat(tmpPath)
	require.NoError(t, err)
	require.True(t, fileInfo.Size() > 0)
}

func TestClose_EmptyResults(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "nuclei-test-empty-*.pdf")
	require.NoError(t, err)
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer func() { _ = os.Remove(tmpPath) }()

	options := &Options{File: tmpPath}
	exporter, err := New(options)
	require.NoError(t, err)

	require.NoError(t, exporter.Close())

	fileInfo, err := os.Stat(tmpPath)
	require.NoError(t, err)
	require.True(t, fileInfo.Size() > 0)
}

func TestClose_IdempotentClose(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "nuclei-test-idempotent-*.pdf")
	require.NoError(t, err)
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer func() { _ = os.Remove(tmpPath) }()

	options := &Options{File: tmpPath}
	exporter, err := New(options)
	require.NoError(t, err)

	event := createMockResultEvent(severity.Info, "INFO-001", "test.com")
	require.NoError(t, exporter.Export(event))

	require.NoError(t, exporter.Close())
	require.NoError(t, exporter.Close())
}
