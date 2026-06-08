// Package sqli implements an error-based SQL injection analyzer for the fuzzer.
//
// It injects a small set of syntax-breaking tokens and looks for database error
// signatures that appear only after injection (a baseline request is taken
// first, so errors already present on the page do not cause false positives).
// Matching a known DBMS error fingerprint is a strong, low-false-positive signal
// that user input reaches a SQL query unsanitized.
package sqli

import (
	"io"
	"regexp"
	"strconv"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

const (
	analyzerName         = "sqli_error"
	maxResponseBodyBytes = 10 * 1024 * 1024 // 10 MiB
)

// Analyzer implements the analyzers.Analyzer interface for error-based SQLi.
type Analyzer struct{}

var _ analyzers.Analyzer = &Analyzer{}

func init() {
	analyzers.RegisterAnalyzer(analyzerName, &Analyzer{})
}

func (a *Analyzer) Name() string {
	return analyzerName
}

func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	return analyzers.ApplyPayloadTransformations(data)
}

// breakingPayloads are tokens that tend to break SQL string/numeric contexts
// and surface a parser error when the input is concatenated into a query.
var breakingPayloads = []string{
	"'",
	"\"",
	"')",
	"';",
	"\")",
	"`",
	"'\"",
	"\\",
}

// dbmsErrorSignature pairs a DBMS name with a regex that matches one of its
// characteristic error strings. Patterns are a curated subset of the
// well-known error-based SQLi fingerprints.
type dbmsErrorSignature struct {
	DBMS  string
	Regex *regexp.Regexp
}

var dbmsErrorSignatures = []dbmsErrorSignature{
	{"MySQL", regexp.MustCompile(`(?i)SQL syntax.*?MySQL`)},
	{"MySQL", regexp.MustCompile(`(?i)check the manual that corresponds to your (MySQL|MariaDB) server version`)},
	{"MySQL", regexp.MustCompile(`(?i)valid MySQL result`)},
	{"MySQL", regexp.MustCompile(`(?i)com\.mysql\.jdbc`)},
	{"MySQL", regexp.MustCompile(`(?i)MySqlException`)},
	{"MariaDB", regexp.MustCompile(`(?i)MariaDB server version for the right syntax`)},
	{"PostgreSQL", regexp.MustCompile(`(?i)PostgreSQL.*?ERROR`)},
	{"PostgreSQL", regexp.MustCompile(`(?i)pg_query\(\):`)},
	{"PostgreSQL", regexp.MustCompile(`(?i)unterminated quoted string at or near`)},
	{"PostgreSQL", regexp.MustCompile(`(?i)org\.postgresql\.util\.PSQLException`)},
	{"Microsoft SQL Server", regexp.MustCompile(`(?i)Unclosed quotation mark after the character string`)},
	{"Microsoft SQL Server", regexp.MustCompile(`(?i)Microsoft SQL (Server|Native Client)`)},
	{"Microsoft SQL Server", regexp.MustCompile(`(?i)System\.Data\.SqlClient\.SqlException`)},
	{"Microsoft SQL Server", regexp.MustCompile(`(?i)Incorrect syntax near`)},
	{"Oracle", regexp.MustCompile(`(?i)ORA-[0-9]{4,5}`)},
	{"Oracle", regexp.MustCompile(`(?i)quoted string not properly terminated`)},
	{"Oracle", regexp.MustCompile(`(?i)oracle\.jdbc`)},
	{"SQLite", regexp.MustCompile(`(?i)SQLite/JDBCDriver`)},
	{"SQLite", regexp.MustCompile(`(?i)SQLite3::query`)},
	{"SQLite", regexp.MustCompile(`(?i)unrecognized token:`)},
	{"SQLite", regexp.MustCompile(`(?i)sqlite3\.OperationalError`)},
	{"IBM DB2", regexp.MustCompile(`(?i)CLI Driver.*?DB2`)},
	{"IBM DB2", regexp.MustCompile(`(?i)DB2 SQL error`)},
	{"Sybase", regexp.MustCompile(`(?i)Sybase message:`)},
}

// MatchDBMSError returns the DBMS whose error signature appears in body, if any.
// It is exported and pure so it can be unit-tested without network access.
func MatchDBMSError(body string) (string, bool) {
	if body == "" {
		return "", false
	}
	for _, sig := range dbmsErrorSignatures {
		if sig.Regex.MatchString(body) {
			return sig.DBMS, true
		}
	}
	return "", false
}

// Analyze injects breaking payloads and reports an error-based SQLi when a DBMS
// error signature appears that was not present in the baseline response.
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	if options == nil || options.FuzzGenerated.Component == nil || options.HttpClient == nil {
		return false, "", nil
	}
	gr := options.FuzzGenerated

	defer func() {
		_ = gr.Component.SetValue(gr.Key, gr.OriginalValue)
	}()

	// Baseline: if the page already shows a DBMS error with the original value,
	// any later match is meaningless, so we bail to avoid false positives.
	baselineBody, err := a.sendAndRead(options, gr.OriginalValue)
	if err != nil {
		return false, "", err
	}
	if _, matched := MatchDBMSError(baselineBody); matched {
		return false, "", nil
	}

	for _, payload := range breakingPayloads {
		body, err := a.sendAndRead(options, gr.OriginalValue+payload)
		if err != nil {
			return false, "", err
		}
		if dbms, matched := MatchDBMSError(body); matched {
			return true, "sqli: " + dbms + " error triggered by payload " + strconv.Quote(payload), nil
		}
	}
	return false, "", nil
}

func (a *Analyzer) sendAndRead(options *analyzers.Options, value string) (string, error) {
	rebuilt, err := analyzers.SetValueAndRebuild(options.FuzzGenerated, value)
	if err != nil {
		return "", err
	}
	resp, err := options.HttpClient.Do(rebuilt)
	if err != nil {
		return "", err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	_ = resp.Body.Close()
	if err != nil {
		return "", err
	}
	return string(body), nil
}
