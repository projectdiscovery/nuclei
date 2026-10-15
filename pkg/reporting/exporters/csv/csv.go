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

// formulaTriggers are the leading characters that Excel, LibreOffice Calc and
// Google Sheets treat as the start of a formula. A cell beginning with one of
// them is evaluated when the file is opened, so a response-derived value such
// as `=cmd|'/C calc'!A0` captured by an extractor would execute on the machine
// of whoever opens the export (CWE-1236).
const formulaTriggers = "=+-@\t\r"

// neutralizeFormula prefixes a single apostrophe to any value a spreadsheet
// would evaluate as a formula, which forces the cell to be read as text.
//
// The transformation is reversible: the original value is the cell with at most
// one leading apostrophe removed. Values that parse as a plain number are left
// untouched so numeric columns (cvss-score, port) stay sortable and a negative
// number is not needlessly quoted.
func neutralizeFormula(value string) string {
	if value == "" || !strings.ContainsRune(formulaTriggers, rune(value[0])) {
		return value
	}
	if _, err := strconv.ParseFloat(value, 64); err == nil {
		return value
	}
	return "'" + value
}

// neutralizeAndJoin newline-joins a multi-value column, neutralizing each
// element rather than only the resulting cell. Consumers routinely split these
// cells back into their individual values, so every element has to be safe on
// its own and not just the first one.
func neutralizeAndJoin(values []string) string {
	if len(values) == 0 {
		return ""
	}
	neutralized := make([]string, 0, len(values))
	for _, value := range values {
		neutralized = append(neutralized, neutralizeFormula(value))
	}
	return strings.Join(neutralized, "\n")
}

// formatRow flattens a ResultEvent into the ordered set of CSV columns defined
// by header. Empty values are emitted for fields that are not present on the
// event (for example, templates without CVE/CVSS classification metadata).
//
// Two separate escaping concerns are handled here. Structural injection is
// handled by encoding/csv, which RFC 4180-quotes any value carrying a comma,
// double quote or newline so it cannot forge extra columns or rows. Spreadsheet
// formula evaluation is handled by neutralizeFormula, because the target of
// this exporter is explicitly a file someone opens in a spreadsheet.
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
		reference = neutralizeAndJoin(event.Info.Reference.ToSlice())
	}

	return []string{
		neutralizeFormula(event.TemplateID),
		neutralizeFormula(event.Info.Name),
		neutralizeFormula(event.Type),
		event.Info.SeverityHolder.Severity.String(),
		neutralizeFormula(event.Host),
		neutralizeFormula(event.IP),
		neutralizeFormula(event.Port),
		neutralizeFormula(event.Matched),
		neutralizeFormula(event.MatcherName),
		neutralizeFormula(event.ExtractorName),
		// Extracted results are arbitrary response-derived data and can contain
		// commas, so they are newline separated inside the (quoted) cell rather
		// than comma separated. CVE/CWE identifiers cannot contain a comma, so
		// those keep the ", " form used everywhere else in nuclei.
		neutralizeAndJoin(event.ExtractedResults),
		cve,
		cwe,
		neutralizeFormula(cvssMetrics),
		cvssScore,
		neutralizeFormula(event.Info.Description),
		reference,
		neutralizeFormula(event.CURLCommand),
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
