package csv

import (
	"encoding/csv"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// Options contains the configuration options for the CSV exporter client
type Options struct {
	// File is the file to export found CSV result to
	File string `yaml:"file"`
}

// header is the ordered list of columns written to the CSV file. The mapping is
// intentionally flat and stable so the output can be ingested directly by
// spreadsheets, SIEM/SOC pipelines and ticketing systems without further
// transformation.
var header = []string{
	"template-id",
	"severity",
	"host",
	"matched-at",
	"cve",
	"cvss",
	"timestamp",
}

// Exporter is an exporter for nuclei results in CSV format
type Exporter struct {
	options    *Options
	mutex      *sync.Mutex
	writer     *csv.Writer
	outputFile *os.File
}

// New creates a new CSV exporter integration client based on options.
func New(options *Options) (*Exporter, error) {
	outputFile, err := os.Create(options.File)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create CSV file")
	}

	writer := csv.NewWriter(outputFile)
	if err := writer.Write(header); err != nil {
		_ = outputFile.Close()
		return nil, errors.Wrap(err, "failed to write CSV header")
	}

	return &Exporter{
		mutex:      &sync.Mutex{},
		options:    options,
		writer:     writer,
		outputFile: outputFile,
	}, nil
}

// Export appends the passed result event as a flattened row to the CSV file
func (exporter *Exporter) Export(event *output.ResultEvent) error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	if err := exporter.writer.Write(formatRow(event)); err != nil {
		return errors.Wrap(err, "failed to write CSV row")
	}

	return nil
}

// formatRow flattens a ResultEvent into the ordered set of CSV columns defined
// by header. Empty values are emitted for fields that are not present on the
// event (for example, templates without CVE/CVSS classification metadata).
func formatRow(event *output.ResultEvent) []string {
	var cve, cvss string
	if event.Info.Classification != nil {
		cve = event.Info.Classification.CVEID.String()
		if event.Info.Classification.CVSSScore > 0 {
			cvss = strconv.FormatFloat(event.Info.Classification.CVSSScore, 'f', -1, 64)
		}
	}

	return []string{
		event.TemplateID,
		event.Info.SeverityHolder.Severity.String(),
		event.Host,
		event.Matched,
		cve,
		cvss,
		event.Timestamp.UTC().Format(time.RFC3339),
	}
}

// Close flushes any buffered rows and closes the CSV file
func (exporter *Exporter) Close() error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	exporter.writer.Flush()
	if err := exporter.writer.Error(); err != nil {
		_ = exporter.outputFile.Close()
		return errors.Wrap(err, "failed to flush CSV file")
	}

	if err := exporter.outputFile.Close(); err != nil {
		return errors.Wrap(err, "failed to close CSV file")
	}

	return nil
}
