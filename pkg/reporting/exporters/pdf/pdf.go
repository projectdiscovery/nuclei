package pdf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/phpdave11/gofpdf"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

const (
	defaultFileName         = "nuclei-report.pdf"
	maxRawBlockRunes        = 2048
	rawBlockTruncatedSuffix = "\n... Truncated ..."
)

var severityColors = map[string][3]int{
	"critical": {139, 0, 0},
	"high":     {255, 69, 0},
	"medium":   {255, 140, 0},
	"low":      {128, 128, 0},
	"info":     {0, 0, 139},
	"unknown":  {128, 128, 128},
}

// Options contains the configuration options for PDF exporter client.
type Options struct {
	// File is the file to export found PDF result to.
	File string `yaml:"file"`
	// OmitRaw removes raw request/response blocks from the exported report.
	OmitRaw bool `yaml:"omit-raw"`
}

// Exporter is an exporter for nuclei PDF output format.
type Exporter struct {
	options *Options
	mu      sync.Mutex
	results []*output.ResultEvent
}

// New creates a new PDF exporter integration client based on options.
func New(options *Options) (*Exporter, error) {
	if options == nil {
		options = &Options{}
	}
	if options.File == "" {
		options.File = defaultFileName
	}
	if dir := filepath.Dir(options.File); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("could not create directory for PDF report: %w", err)
		}
	}
	return &Exporter{
		options: options,
		results: make([]*output.ResultEvent, 0),
	}, nil
}

// Export exports a passed result event to the PDF exporter.
func (e *Exporter) Export(event *output.ResultEvent) error {
	if event == nil {
		return nil
	}

	eventCopy := *event
	e.mu.Lock()
	e.results = append(e.results, &eventCopy)
	e.mu.Unlock()

	return nil
}

// Close writes the PDF file and closes the exporter after operation.
func (e *Exporter) Close() error {
	e.mu.Lock()
	if len(e.results) == 0 {
		e.mu.Unlock()
		return nil
	}
	results := append([]*output.ResultEvent(nil), e.results...)
	e.mu.Unlock()

	return e.generatePDF(results)
}

func (e *Exporter) generatePDF(results []*output.ResultEvent) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)
	pdf.SetAutoPageBreak(true, 15)
	pdf.SetCompression(false)

	pdf.SetFooterFunc(func() {
		pdf.SetY(-13)
		pdf.SetFont("Helvetica", "I", 8)
		pdf.SetTextColor(128, 128, 128)
		pdf.CellFormat(0, 8, fmt.Sprintf("Page %d | Nuclei %s", pdf.PageNo(), config.Version), "", 0, "C", false, 0, "")
	})

	pdf.AddPage()
	e.writeHeader(pdf, len(results))
	e.writeSeveritySummary(pdf, results)
	e.writeFindingsTable(pdf, results)
	e.writeDetailedFindings(pdf, results)

	if err := pdf.OutputFileAndClose(e.options.File); err != nil {
		return fmt.Errorf("failed to write PDF report: %w", err)
	}
	return nil
}

func (e *Exporter) writeHeader(pdf *gofpdf.Fpdf, total int) {
	pdf.SetFont("Helvetica", "B", 18)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(0, 10, "Nuclei Scan Report", "", 1, "C", false, 0, "")

	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(90, 90, 90)
	pdf.CellFormat(0, 6, fmt.Sprintf("Generated: %s", time.Now().UTC().Format("2006-01-02 15:04:05 UTC")), "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 6, fmt.Sprintf("Version: %s", config.Version), "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 6, fmt.Sprintf("Total Findings: %d", total), "", 1, "C", false, 0, "")
	pdf.Ln(5)
}

func (e *Exporter) writeSeveritySummary(pdf *gofpdf.Fpdf, results []*output.ResultEvent) {
	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
		"unknown":  0,
	}

	for _, result := range results {
		if result == nil {
			continue
		}
		severity := strings.ToLower(result.Info.SeverityHolder.Severity.String())
		if _, ok := counts[severity]; ok {
			counts[severity]++
			continue
		}
		counts["unknown"]++
	}

	pdf.SetFont("Helvetica", "B", 13)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(0, 8, "Severity Summary", "", 1, "L", false, 0, "")
	pdf.Ln(1)

	pdf.SetFont("Helvetica", "", 10)
	orderedSeverities := []string{"critical", "high", "medium", "low", "info", "unknown"}
	for _, sev := range orderedSeverities {
		count := counts[sev]
		if count == 0 {
			continue
		}
		color := severityColor(sev)
		pdf.SetTextColor(color[0], color[1], color[2])
		pdf.CellFormat(0, 6, fmt.Sprintf("%s: %d", strings.ToUpper(sev), count), "", 1, "L", false, 0, "")
	}
	pdf.SetTextColor(0, 0, 0)
	pdf.Ln(2)
}

func (e *Exporter) writeFindingsTable(pdf *gofpdf.Fpdf, results []*output.ResultEvent) {
	pdf.SetFont("Helvetica", "B", 13)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(0, 8, "Findings Overview", "", 1, "L", false, 0, "")
	pdf.Ln(1)

	pdf.SetFont("Helvetica", "B", 9)
	pdf.SetFillColor(235, 235, 235)
	colWidths := []float64{22, 45, 40, 45, 28}
	headers := []string{"Severity", "Template", "Host", "Matched", "Timestamp"}
	for i, header := range headers {
		pdf.CellFormat(colWidths[i], 7, header, "1", 0, "C", true, 0, "")
	}
	pdf.Ln(-1)

	pdf.SetFont("Helvetica", "", 8)
	for _, result := range results {
		if result == nil {
			continue
		}

		severity := strings.ToLower(result.Info.SeverityHolder.Severity.String())
		color := severityColor(severity)
		pdf.SetTextColor(color[0], color[1], color[2])
		pdf.CellFormat(colWidths[0], 6, strings.ToUpper(severity), "1", 0, "C", false, 0, "")

		pdf.SetTextColor(0, 0, 0)
		pdf.CellFormat(colWidths[1], 6, truncateRunes(result.TemplateID, 28), "1", 0, "L", false, 0, "")
		pdf.CellFormat(colWidths[2], 6, truncateRunes(result.Host, 25), "1", 0, "L", false, 0, "")
		pdf.CellFormat(colWidths[3], 6, truncateRunes(result.Matched, 28), "1", 0, "L", false, 0, "")
		pdf.CellFormat(colWidths[4], 6, formatTimestamp(result.Timestamp), "1", 0, "C", false, 0, "")
		pdf.Ln(-1)
	}
	pdf.Ln(2)
}

func (e *Exporter) writeDetailedFindings(pdf *gofpdf.Fpdf, results []*output.ResultEvent) {
	for idx, result := range results {
		if result == nil {
			continue
		}

		pdf.AddPage()
		severity := strings.ToLower(result.Info.SeverityHolder.Severity.String())
		color := severityColor(severity)

		pdf.SetFont("Helvetica", "B", 13)
		pdf.SetTextColor(color[0], color[1], color[2])
		pdf.CellFormat(0, 8, fmt.Sprintf("#%d [%s] %s", idx+1, strings.ToUpper(severity), truncateRunes(result.Info.Name, 80)), "", 1, "L", false, 0, "")

		pdf.SetTextColor(0, 0, 0)
		pdf.SetFont("Helvetica", "", 10)
		writeField(pdf, "Template", result.TemplateID)
		writeField(pdf, "Host", result.Host)
		writeField(pdf, "Matched", result.Matched)
		writeField(pdf, "Protocol", strings.ToUpper(result.Type))
		writeField(pdf, "Timestamp", formatFullTimestamp(result.Timestamp))

		if result.Info.Description != "" {
			pdf.Ln(1)
			pdf.SetFont("Helvetica", "B", 10)
			pdf.CellFormat(0, 6, "Description:", "", 1, "L", false, 0, "")
			pdf.SetFont("Helvetica", "", 9)
			pdf.MultiCell(0, 5, result.Info.Description, "", "L", false)
		}

		if result.Info.Reference != nil && !result.Info.Reference.IsEmpty() {
			pdf.Ln(1)
			pdf.SetFont("Helvetica", "B", 10)
			pdf.CellFormat(0, 6, "References:", "", 1, "L", false, 0, "")
			pdf.SetFont("Helvetica", "", 9)
			for _, ref := range result.Info.Reference.ToSlice() {
				pdf.CellFormat(0, 5, "- "+truncateRunes(ref, 110), "", 1, "L", false, 0, "")
			}
		}

		if len(result.ExtractedResults) > 0 {
			pdf.Ln(1)
			pdf.SetFont("Helvetica", "B", 10)
			pdf.CellFormat(0, 6, "Extracted Results:", "", 1, "L", false, 0, "")
			pdf.SetFont("Helvetica", "", 9)
			for _, value := range result.ExtractedResults {
				pdf.CellFormat(0, 5, "- "+truncateRunes(value, 110), "", 1, "L", false, 0, "")
			}
		}

		if e.options.OmitRaw {
			continue
		}
		if result.Request != "" {
			writeCodeBlock(pdf, "Request", result.Request)
		}
		if result.Response != "" {
			writeCodeBlock(pdf, "Response", result.Response)
		}
	}
}

func writeField(pdf *gofpdf.Fpdf, label, value string) {
	if value == "" {
		return
	}
	pdf.SetFont("Helvetica", "B", 10)
	pdf.CellFormat(28, 6, label+":", "", 0, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 10)
	pdf.CellFormat(0, 6, truncateRunes(value, 110), "", 1, "L", false, 0, "")
}

func writeCodeBlock(pdf *gofpdf.Fpdf, title, content string) {
	pdf.Ln(1)
	pdf.SetFont("Helvetica", "B", 10)
	pdf.CellFormat(0, 6, title+":", "", 1, "L", false, 0, "")

	pdf.SetFont("Courier", "", 7)
	pdf.SetFillColor(245, 245, 245)
	pdf.MultiCell(0, 4, truncateRawBlock(content), "1", "L", true)
	pdf.SetFont("Helvetica", "", 10)
}

func truncateRawBlock(content string) string {
	runes := []rune(content)
	if len(runes) <= maxRawBlockRunes {
		return content
	}
	return string(runes[:maxRawBlockRunes]) + rawBlockTruncatedSuffix
}

func truncateRunes(value string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= maxLen {
		return value
	}
	if maxLen <= 3 {
		return strings.Repeat(".", maxLen)
	}
	return string(runes[:maxLen-3]) + "..."
}

func severityColor(severity string) [3]int {
	if color, ok := severityColors[severity]; ok {
		return color
	}
	return severityColors["unknown"]
}

func formatTimestamp(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.UTC().Format("15:04:05")
}

func formatFullTimestamp(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.UTC().Format("2006-01-02 15:04:05 UTC")
}
