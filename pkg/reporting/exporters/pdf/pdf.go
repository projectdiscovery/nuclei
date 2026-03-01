package pdf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-pdf/fpdf"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// Options contains the configuration options for PDF exporter
type Options struct {
	// File is the output PDF file path
	File    string `yaml:"file"`
	OmitRaw bool   `yaml:"omit-raw"`
}

// Exporter is a PDF exporter for nuclei scan results
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
		options.File = "nuclei-report.pdf"
	}
	// Validate file path to prevent directory traversal (CWE-22)
	cleanPath := filepath.Clean(options.File)
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("invalid file path: %w", err)
	}
	
	// Reject absolute paths to prevent arbitrary file writes
	if filepath.IsAbs(options.File) {
		return nil, fmt.Errorf("absolute paths not permitted for security: %s", options.File)
	}
	
	// Ensure relative paths stay within the current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("could not get working directory: %w", err)
	}
	
	expectedPrefix := filepath.Join(cwd, "")
	if !strings.HasPrefix(absPath+string(filepath.Separator), expectedPrefix) {
		return nil, fmt.Errorf("file path escapes working directory: %s", options.File)
	}
	
	options.File = absPath
	dir := filepath.Dir(options.File)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("could not create directory for PDF report: %w", err)
		}
	}
	return &Exporter{options: options}, nil
}

// Export collects a result event for later PDF generation
func (e *Exporter) Export(event *output.ResultEvent) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.results = append(e.results, event)
	return nil
}

// Close generates the PDF report and writes it to disk
func (e *Exporter) Close() error {
	e.mu.Lock()
	if len(e.results) == 0 {
		e.mu.Unlock()
		return nil
	}
	// Snapshot results under lock to avoid race with concurrent Export calls
	results := append([]*output.ResultEvent(nil), e.results...)
	e.mu.Unlock()
	return e.generatePDF(results)
}


func (e *Exporter) generatePDF(results []*output.ResultEvent) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 15)

	// Title page
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 24)
	pdf.CellFormat(0, 20, "Nuclei Scan Report", "", 1, "C", false, 0, "")
	pdf.SetFont("Helvetica", "", 12)
	pdf.CellFormat(0, 10, fmt.Sprintf("Generated: %s", time.Now().Format("2006-01-02 15:04:05")), "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 10, fmt.Sprintf("Total Findings: %d", len(results)), "", 1, "C", false, 0, "")
	pdf.Ln(10)

	// Severity summary
	severityCounts := map[string]int{}
	for _, r := range results {
		sev := r.Info.SeverityHolder.Severity.String()
		severityCounts[sev]++
	}
	e.writeSeveritySummary(pdf, severityCounts)
	pdf.Ln(10)

	// Findings table
	e.writeFindingsTable(pdf, results)

	// Detailed findings
	for i, r := range results {
		pdf.AddPage()
		e.writeDetailedFinding(pdf, i+1, r)
	}

	return pdf.OutputFileAndClose(e.options.File)
}

var severityColors = map[string][3]int{
	"critical": {153, 0, 0},
	"high":     {255, 0, 0},
	"medium":   {255, 165, 0},
	"low":      {0, 128, 0},
	"info":     {0, 0, 255},
	"unknown":  {128, 128, 128},
}

func (e *Exporter) writeSeveritySummary(pdf *fpdf.Fpdf, counts map[string]int) {
	pdf.SetFont("Helvetica", "B", 14)
	pdf.CellFormat(0, 10, "Severity Summary", "", 1, "L", false, 0, "")

	pdf.SetFont("Helvetica", "", 11)
	for _, sev := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		count, ok := counts[sev]
		if !ok {
			continue
		}
		r, g, b := severityColors[sev][0], severityColors[sev][1], severityColors[sev][2]
		pdf.SetTextColor(r, g, b)
		pdf.CellFormat(0, 7, fmt.Sprintf("  %s: %d", strings.ToUpper(sev), count), "", 1, "L", false, 0, "")
	}
	pdf.SetTextColor(0, 0, 0)
}

func (e *Exporter) writeFindingsTable(pdf *fpdf.Fpdf, results []*output.ResultEvent) {
	pdf.SetFont("Helvetica", "B", 14)
	pdf.CellFormat(0, 10, "Findings Overview", "", 1, "L", false, 0, "")

	// Table header
	pdf.SetFont("Helvetica", "B", 9)
	pdf.SetFillColor(220, 220, 220)
	colWidths := []float64{60, 50, 50, 30}
	headers := []string{"Host", "Template", "Name", "Severity"}
	for i, h := range headers {
		pdf.CellFormat(colWidths[i], 8, h, "1", 0, "C", true, 0, "")
	}
	pdf.Ln(-1)

	// Table rows
	pdf.SetFont("Helvetica", "", 8)
	for _, r := range results {
		host := truncate(r.Host, 35)
		tmpl := truncate(r.TemplateID, 28)
		name := truncate(r.Info.Name, 28)
		sev := r.Info.SeverityHolder.Severity.String()

		// Set severity color for the row
		if c, ok := severityColors[sev]; ok {
			pdf.SetTextColor(c[0], c[1], c[2])
		}

		pdf.CellFormat(colWidths[0], 7, host, "1", 0, "L", false, 0, "")
		pdf.CellFormat(colWidths[1], 7, tmpl, "1", 0, "L", false, 0, "")
		pdf.CellFormat(colWidths[2], 7, name, "1", 0, "L", false, 0, "")
		pdf.CellFormat(colWidths[3], 7, strings.ToUpper(sev), "1", 0, "C", false, 0, "")
		pdf.Ln(-1)
		pdf.SetTextColor(0, 0, 0)
	}
}

func (e *Exporter) writeDetailedFinding(pdf *fpdf.Fpdf, index int, r *output.ResultEvent) {
	// Title
	pdf.SetFont("Helvetica", "B", 14)
	sev := r.Info.SeverityHolder.Severity.String()
	if c, ok := severityColors[sev]; ok {
		pdf.SetTextColor(c[0], c[1], c[2])
	}
	pdf.CellFormat(0, 10, fmt.Sprintf("#%d [%s] %s", index, strings.ToUpper(sev), r.Info.Name), "", 1, "L", false, 0, "")
	pdf.SetTextColor(0, 0, 0)

	// Metadata
	pdf.SetFont("Helvetica", "", 10)
	writeField(pdf, "Template", r.TemplateID)
	writeField(pdf, "Host", r.Host)
	writeField(pdf, "Matched", r.Matched)
	writeField(pdf, "Protocol", strings.ToUpper(r.Type))
	writeField(pdf, "Timestamp", r.Timestamp.Format("2006-01-02 15:04:05"))

	if r.Info.Description != "" {
		pdf.Ln(3)
		pdf.SetFont("Helvetica", "B", 10)
		pdf.CellFormat(0, 7, "Description:", "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		pdf.MultiCell(0, 5, r.Info.Description, "", "L", false)
	}

	if r.Info.Reference != nil && !r.Info.Reference.IsEmpty() {
		pdf.Ln(3)
		pdf.SetFont("Helvetica", "B", 10)
		pdf.CellFormat(0, 7, "References:", "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		for _, ref := range r.Info.Reference.ToSlice() {
			pdf.CellFormat(0, 5, fmt.Sprintf("  - %s", ref), "", 1, "L", false, 0, "")
		}
	}

	if len(r.ExtractedResults) > 0 {
		pdf.Ln(3)
		pdf.SetFont("Helvetica", "B", 10)
		pdf.CellFormat(0, 7, "Extracted Results:", "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		for _, v := range r.ExtractedResults {
			pdf.CellFormat(0, 5, fmt.Sprintf("  - %s", v), "", 1, "L", false, 0, "")
		}
	}

	if !e.options.OmitRaw {
		if r.Request != "" {
			writeCodeBlock(pdf, "Request", r.Request)
		}
		if r.Response != "" {
			writeCodeBlock(pdf, "Response", r.Response)
		}
	}
}

func writeField(pdf *fpdf.Fpdf, label, value string) {
	if value == "" {
		return
	}
	pdf.SetFont("Helvetica", "B", 10)
	pdf.CellFormat(30, 7, label+":", "", 0, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 10)
	pdf.CellFormat(0, 7, value, "", 1, "L", false, 0, "")
}

func writeCodeBlock(pdf *fpdf.Fpdf, title, content string) {
	pdf.Ln(3)
	pdf.SetFont("Helvetica", "B", 10)
	pdf.CellFormat(0, 7, title+":", "", 1, "L", false, 0, "")
	pdf.SetFont("Courier", "", 7)
	pdf.SetFillColor(245, 245, 245)
	// Limit content length to avoid oversized PDFs
	if len(content) > 2048 {
		content = content[:2048] + "\n.... Truncated ...."
	}
	pdf.MultiCell(0, 4, content, "1", "L", true)
	pdf.SetFont("Helvetica", "", 10)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
