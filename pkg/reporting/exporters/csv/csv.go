package csv

import (
	"encoding/csv"
	"os"
	"strconv"
	"strings"
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

// header is the ordered list of columns written to the CSV file.
//
// The schema is a flattened full row of the result event: everything a triage
// or GRC workflow normally needs is present as its own column, so the file can
// be opened in a spreadsheet or handed to a ticketing/SIEM intake without any
// further transformation.
//
// Column names mirror the JSON/JSONL keys of output.ResultEvent one-for-one so
// a column can always be traced back to the field it came from, and match the
// names httpx uses in its own CSV mode where they overlap (host, port,
// timestamp). The two exceptions are template-name and template-type, which map
// to info.name and type: bare "name"/"type" are ambiguous as spreadsheet
// headers.
var header = []string{
	"template-id",
	"template-name",
	"template-type",
	"severity",
	"host",
	"ip",
	"port",
	"matched-at",
	"matcher-name",
	"extractor-name",
	"extracted-results",
	"cve-id",
	"cwe-id",
	"cvss-metrics",
	"cvss-score",
	"description",
	"reference",
	"curl-command",
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
	writer.Flush()
	if err := writer.Error(); err != nil {
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

// Export appends the passed result event as a flattened row to the CSV file.
// Rows are flushed as they are written so the file is complete and readable
// while a long scan is still running.
func (exporter *Exporter) Export(event *output.ResultEvent) error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	if err := exporter.writer.Write(formatRow(event)); err != nil {
		return errors.Wrap(err, "failed to write CSV row")
	}
	exporter.writer.Flush()
	if err := exporter.writer.Error(); err != nil {
		return errors.Wrap(err, "failed to write CSV row")
	}

	return nil
}

// formatRow flattens a ResultEvent into the ordered set of CSV columns defined
// by header. Empty values are emitted for fields that are not present on the
// event (for example, templates without CVE/CVSS classification metadata).
//
// Every value is handed to encoding/csv unmodified, so values carrying commas,
// double quotes or newlines are quoted per RFC 4180 instead of breaking the
// column layout.
func formatRow(event *output.ResultEvent) []string {
	var cve, cwe, cvssMetrics, cvssScore string
	if event.Info.Classification != nil {
		classification := event.Info.Classification
		cve = classification.CVEID.String()
		cwe = classification.CWEID.String()
		cvssMetrics = classification.CVSSMetrics
		if classification.CVSSScore > 0 {
			cvssScore = strconv.FormatFloat(classification.CVSSScore, 'f', -1, 64)
		}
	}

	// References are URLs and can themselves contain a comma, so they are
	// newline separated inside the (quoted) cell rather than comma separated.
	var reference string
	if event.Info.Reference != nil {
		reference = strings.Join(event.Info.Reference.ToSlice(), "\n")
	}

	return []string{
		event.TemplateID,
		event.Info.Name,
		event.Type,
		event.Info.SeverityHolder.Severity.String(),
		event.Host,
		event.IP,
		event.Port,
		event.Matched,
		event.MatcherName,
		event.ExtractorName,
		// Extracted results are arbitrary response-derived data and can contain
		// commas, so they are newline separated inside the (quoted) cell rather
		// than comma separated. CVE/CWE identifiers cannot contain a comma, so
		// those keep the ", " form used everywhere else in nuclei.
		strings.Join(event.ExtractedResults, "\n"),
		cve,
		cwe,
		cvssMetrics,
		cvssScore,
		event.Info.Description,
		reference,
		event.CURLCommand,
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
