package csv

import (
	encodingcsv "encoding/csv"
	"os"
	"path/filepath"
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

func TestCSVExporterWritesHeaderAndFlattenedRows(t *testing.T) {
	file := filepath.Join(t.TempDir(), "results.csv")

	exporter, err := New(&Options{File: file})
	require.NoError(t, err)

	ts := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	event := &output.ResultEvent{
		TemplateID: "CVE-2021-44228",
		Info: model.Info{
			SeverityHolder: severity.Holder{Severity: severity.Critical},
			Classification: &model.Classification{
				CVEID:     stringslice.StringSlice{Value: "CVE-2021-44228"},
				CVSSScore: 10.0,
			},
		},
		Host:      "https://example.com",
		Matched:   "https://example.com/api",
		Timestamp: ts,
	}

	require.NoError(t, exporter.Export(event))
	require.NoError(t, exporter.Close())

	records := readCSV(t, file)
	require.Len(t, records, 2, "expected header + one data row")
	require.Equal(t, header, records[0])
	require.Equal(t, []string{
		"CVE-2021-44228",
		"critical",
		"https://example.com",
		"https://example.com/api",
		"CVE-2021-44228",
		"10",
		"2025-01-02T03:04:05Z",
	}, records[1])
}

func TestCSVExporterHandlesMissingClassification(t *testing.T) {
	file := filepath.Join(t.TempDir(), "results.csv")

	exporter, err := New(&Options{File: file})
	require.NoError(t, err)

	event := &output.ResultEvent{
		TemplateID: "tech-detect",
		Info: model.Info{
			SeverityHolder: severity.Holder{Severity: severity.Info},
		},
		Host:      "example.org",
		Matched:   "example.org",
		Timestamp: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	}

	require.NoError(t, exporter.Export(event))
	require.NoError(t, exporter.Close())

	records := readCSV(t, file)
	require.Len(t, records, 2)
	// cve and cvss columns must be empty, not "0" or "<nil>", when the template
	// carries no classification metadata.
	require.Equal(t, "", records[1][4])
	require.Equal(t, "", records[1][5])
	require.Equal(t, "info", records[1][1])
}

func TestCSVExporterEscapesInjectionProneFields(t *testing.T) {
	file := filepath.Join(t.TempDir(), "results.csv")

	exporter, err := New(&Options{File: file})
	require.NoError(t, err)

	// Host/matched-at are attacker-influenced. Values containing commas,
	// quotes and newlines must round-trip through encoding/csv without
	// corrupting the column layout.
	event := &output.ResultEvent{
		TemplateID: "weird,id\"with\nnewline",
		Info: model.Info{
			SeverityHolder: severity.Holder{Severity: severity.High},
		},
		Host:      "a,b\"c",
		Matched:   "line1\nline2",
		Timestamp: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	}

	require.NoError(t, exporter.Export(event))
	require.NoError(t, exporter.Close())

	records := readCSV(t, file)
	require.Len(t, records, 2)
	require.Equal(t, "weird,id\"with\nnewline", records[1][0])
	require.Equal(t, "a,b\"c", records[1][2])
	require.Equal(t, "line1\nline2", records[1][3])
}

func TestCSVExporterJoinsMultipleCVEs(t *testing.T) {
	file := filepath.Join(t.TempDir(), "results.csv")

	exporter, err := New(&Options{File: file})
	require.NoError(t, err)

	event := &output.ResultEvent{
		TemplateID: "multi-cve",
		Info: model.Info{
			SeverityHolder: severity.Holder{Severity: severity.Medium},
			Classification: &model.Classification{
				CVEID:     stringslice.StringSlice{Value: []string{"CVE-2020-0001", "CVE-2020-0002"}},
				CVSSScore: 5.5,
			},
		},
		Host:      "example.net",
		Matched:   "example.net",
		Timestamp: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	}

	require.NoError(t, exporter.Export(event))
	require.NoError(t, exporter.Close())

	records := readCSV(t, file)
	require.Len(t, records, 2)
	require.Equal(t, "CVE-2020-0001, CVE-2020-0002", records[1][4])
	require.Equal(t, "5.5", records[1][5])
}
