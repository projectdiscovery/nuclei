package csv

import (
	"encoding/csv"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

const (
	// defaultFile is used when no file is configured, mirroring the PDF
	// exporter. The generated default reporting config lists every exporter with
	// an empty block, and an empty block must not stop the client from starting.
	defaultFile = "nuclei-results.csv"

	// filePerm keeps the export private to the current user. Rows carry
	// extracted response data and a replayable curl command, which can include
	// credentials, so the file is not world readable by default.
	filePerm = 0o600

	// multiValueSeparator separates the elements of a multi-value cell.
	multiValueSeparator = "\n"
)

// Options contains the configuration options for the CSV exporter client
type Options struct {
	// File is the file to export found CSV result to
	File string `yaml:"file"`
	// OmitRaw whether to leave the curl command, which is a rendering of the raw
	// request, out of the export
	OmitRaw bool `yaml:"omit-raw"`
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
	closed     bool
}

// New creates a new CSV exporter integration client based on options.
func New(options *Options) (*Exporter, error) {
	opts := &Options{}
	if options != nil {
		*opts = *options
	}
	if opts.File == "" {
		opts.File = defaultFile
	}

	outputFile, err := os.OpenFile(opts.File, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, filePerm)
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
		options:    opts,
		writer:     writer,
		outputFile: outputFile,
	}, nil
}

// Export appends the passed result event as a flattened row to the CSV file.
// Rows are flushed as they are written so the file is complete and readable
// while a long scan is still running. The event is only read, never modified,
// because the same event is handed to every exporter and tracker.
func (exporter *Exporter) Export(event *output.ResultEvent) error {
	if event == nil {
		return nil
	}

	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	if exporter.closed {
		return errors.New("CSV exporter is closed")
	}

	if err := exporter.writer.Write(formatRow(event, exporter.options.OmitRaw)); err != nil {
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

// plainNumber matches a value that is only a decimal number. It is used to keep
// numeric cells such as a negative extracted value sortable. It is deliberately
// stricter than strconv.ParseFloat, which also accepts forms like "+Inf",
// "-NaN" and hex floats that a spreadsheet does not read as numbers.
var plainNumber = regexp.MustCompile(`^[+-]?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?$`)

// startsWithFormulaTrigger reports whether a spreadsheet would read the value
// as a formula. Leading spaces and control characters are skipped first,
// because some spreadsheets ignore them before the trigger.
func startsWithFormulaTrigger(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if strings.IndexByte(formulaTriggers, c) >= 0 {
			return true
		}
		if c > ' ' {
			return false
		}
	}
	return false
}

// neutralizeFormula prefixes a single apostrophe to any value a spreadsheet
// would evaluate as a formula, which forces the cell to be read as text.
//
// The original value is recovered by removing one leading apostrophe, except
// for a value that already started with an apostrophe, which is left alone and
// is therefore indistinguishable from a neutralized one. Values that are only a
// plain number are left untouched so numeric columns (cvss-score, port) stay
// sortable and a negative number is not needlessly quoted.
func neutralizeFormula(value string) string {
	if !startsWithFormulaTrigger(value) || plainNumber.MatchString(value) {
		return value
	}
	return "'" + value
}

// neutralizeLines neutralizes every line of a value that is stored as a list
// of lines. Consumers split these cells back into lines, so each line has to be
// safe on its own and not just the start of the cell. Line endings are
// normalized to a single newline, which is the separator of the list.
func neutralizeLines(value string) string {
	if value == "" {
		return ""
	}
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	lines := strings.Split(value, "\n")
	for i, line := range lines {
		lines[i] = neutralizeFormula(line)
	}
	return strings.Join(lines, "\n")
}

// neutralizeList joins the elements of a multi-value column with the given
// separator after neutralizing each element, and each line of each element.
func neutralizeList(values []string, separator string) string {
	if len(values) == 0 {
		return ""
	}
	neutralized := make([]string, 0, len(values))
	for _, value := range values {
		neutralized = append(neutralized, neutralizeLines(value))
	}
	return strings.Join(neutralized, separator)
}

// formatRow flattens a ResultEvent into the ordered set of CSV columns defined
// by header. Empty values are emitted for fields that are not present on the
// event (for example, templates without CVE/CVSS classification metadata).
//
// Two separate escaping concerns are handled here. Structural injection is
// handled by encoding/csv, which RFC 4180-quotes any value carrying a comma,
// double quote or newline so it cannot forge extra columns or rows. Spreadsheet
// formula evaluation is handled by neutralizeFormula, because the target of
// this exporter is explicitly a file someone opens in a spreadsheet. Every
// column goes through it, including the ones that normally hold a controlled
// value, because template metadata is written by the template author and is not
// trusted either.
func formatRow(event *output.ResultEvent, omitRaw bool) []string {
	var cve, cwe, cvssMetrics, cvssScore string
	if event.Info.Classification != nil {
		classification := event.Info.Classification
		// CVE/CWE identifiers cannot contain a comma, so they keep the ", "
		// form used everywhere else in nuclei.
		cve = neutralizeList(classification.CVEID.ToSlice(), ", ")
		cwe = neutralizeList(classification.CWEID.ToSlice(), ", ")
		cvssMetrics = classification.CVSSMetrics
		if classification.CVSSScore > 0 {
			cvssScore = strconv.FormatFloat(classification.CVSSScore, 'f', -1, 64)
		}
	}

	// References are URLs and can themselves contain a comma, so they are
	// newline separated inside the (quoted) cell rather than comma separated.
	var reference string
	if event.Info.Reference != nil {
		reference = neutralizeList(event.Info.Reference.ToSlice(), multiValueSeparator)
	}

	var curlCommand string
	if !omitRaw {
		curlCommand = event.CURLCommand
	}

	var timestamp string
	if !event.Timestamp.IsZero() {
		timestamp = event.Timestamp.UTC().Format(time.RFC3339)
	}

	return []string{
		neutralizeFormula(event.TemplateID),
		neutralizeFormula(event.Info.Name),
		neutralizeFormula(event.Type),
		neutralizeFormula(event.Info.SeverityHolder.Severity.String()),
		neutralizeFormula(event.Host),
		neutralizeFormula(event.IP),
		neutralizeFormula(event.Port),
		neutralizeFormula(event.Matched),
		neutralizeFormula(event.MatcherName),
		neutralizeFormula(event.ExtractorName),
		// Extracted results are arbitrary response-derived data and can contain
		// commas and newlines, so they are newline separated inside the
		// (quoted) cell, with every line neutralized on its own.
		neutralizeList(event.ExtractedResults, multiValueSeparator),
		cve,
		cwe,
		neutralizeFormula(cvssMetrics),
		neutralizeFormula(cvssScore),
		neutralizeFormula(event.Info.Description),
		reference,
		neutralizeFormula(curlCommand),
		neutralizeFormula(timestamp),
	}
}

// Close flushes any buffered rows and closes the CSV file. It is safe to call
// more than once.
func (exporter *Exporter) Close() error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	if exporter.closed {
		return nil
	}
	exporter.closed = true

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
