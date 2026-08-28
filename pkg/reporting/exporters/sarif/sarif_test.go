package sarif

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

func TestSarifExportIncludesConfidence(t *testing.T) {
	file := filepath.Join(t.TempDir(), "out.sarif")
	exporter, err := New(&Options{File: file})
	require.NoError(t, err)

	event := &output.ResultEvent{
		TemplateID: "test-template",
		Host:       "example.com",
		Path:       "/x",
		Info: model.Info{
			Name:           "Test Template",
			Description:    "desc",
			SeverityHolder: severity.Holder{Severity: severity.High},
		},
		Confidence:      "high",
		ConfidenceScore: 85,
	}
	require.NoError(t, exporter.Export(event))
	require.NoError(t, exporter.Close())

	data, err := os.ReadFile(file)
	require.NoError(t, err)
	require.Contains(t, string(data), "confidence")
	require.Contains(t, string(data), "confidence-score")
}
