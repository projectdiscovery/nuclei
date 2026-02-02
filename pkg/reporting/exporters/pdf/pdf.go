package pdf

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jung-kurt/gofpdf"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// Options contains the configuration options for PDF exporter client
type Options struct {
	// File is the file to export found PDF result to
	File string `yaml:"file"`
}

// Exporter is an exporter for nuclei PDF output format.
type Exporter struct {
	options *Options
	mutex   *sync.Mutex
	results []*output.ResultEvent
}

// New creates a new PDF exporter integration client based on options.
func New(options *Options) (*Exporter, error) {
	exporter := &Exporter{
		options: options,
		mutex:   &sync.Mutex{},
		results: make([]*output.ResultEvent, 0),
	}
	return exporter, nil
}

// Export exports a passed result event to the PDF exporter
func (exporter *Exporter) Export(event *output.ResultEvent) error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	if event == nil {
		return nil
	}

	exporter.results = append(exporter.results, event)
	return nil
}

// Close writes the PDF file and closes the exporter after operation
func (exporter *Exporter) Close() error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)
	pdf.SetAutoPageBreak(true, 15)
	pdf.AddPage()

	// Header
	pdf.SetFont("Arial", "B", 18)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(0, 12, "Nuclei Vulnerability Scan Report", "", 1, "C", false, 0, "")

	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(100, 100, 100)
	pdf.CellFormat(0, 6, fmt.Sprintf("Generated: %s", time.Now().Format("2006-01-02 15:04:05")), "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 6, fmt.Sprintf("Nuclei Version: %s", config.Version), "", 1, "C", false, 0, "")
	pdf.Ln(8)

	if len(exporter.results) == 0 {
		// No findings message
		pdf.SetFont("Arial", "I", 12)
		pdf.SetTextColor(0, 128, 0)
		pdf.CellFormat(0, 10, "No findings detected during the scan.", "", 1, "C", false, 0, "")
	} else {
		// Severity summary
		exporter.writeSeveritySummary(pdf)
		pdf.Ln(8)

		// Findings table
		exporter.writeFindingsTable(pdf)
		pdf.Ln(8)

		// Detailed findings
		exporter.writeDetailedFindings(pdf)
	}

	// Footer is handled by page break callback
	pdf.SetFooterFunc(func() {
		pdf.SetY(-15)
		pdf.SetFont("Arial", "I", 8)
		pdf.SetTextColor(128, 128, 128)
		pdf.CellFormat(0, 10, fmt.Sprintf("Page %d | Nuclei %s", pdf.PageNo(), config.Version), "", 0, "C", false, 0, "")
	})

	// Write to file
	if err := pdf.OutputFileAndClose(exporter.options.File); err != nil {
		return fmt.Errorf("failed to write PDF file: %w", err)
	}

	return nil
}

// writeSeveritySummary writes the severity summary section
func (exporter *Exporter) writeSeveritySummary(pdf *gofpdf.Fpdf) {
	severityCounts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
		"unknown":  0,
	}

	for _, result := range exporter.results {
		severity := strings.ToLower(result.Info.SeverityHolder.Severity.String())
		if _, ok := severityCounts[severity]; ok {
			severityCounts[severity]++
		} else {
			severityCounts["unknown"]++
		}
	}

	pdf.SetFont("Arial", "B", 14)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(0, 8, "Severity Summary", "", 1, "L", false, 0, "")
	pdf.Ln(2)

	pdf.SetFont("Arial", "", 10)

	// Critical - Red
	pdf.SetTextColor(139, 0, 0)
	pdf.CellFormat(0, 6, fmt.Sprintf("Critical: %d", severityCounts["critical"]), "", 1, "L", false, 0, "")

	// High - Orange Red
	pdf.SetTextColor(255, 69, 0)
	pdf.CellFormat(0, 6, fmt.Sprintf("High: %d", severityCounts["high"]), "", 1, "L", false, 0, "")

	// Medium - Orange
	pdf.SetTextColor(255, 165, 0)
	pdf.CellFormat(0, 6, fmt.Sprintf("Medium: %d", severityCounts["medium"]), "", 1, "L", false, 0, "")

	// Low - Yellow/Olive
	pdf.SetTextColor(128, 128, 0)
	pdf.CellFormat(0, 6, fmt.Sprintf("Low: %d", severityCounts["low"]), "", 1, "L", false, 0, "")

	// Info - Blue
	pdf.SetTextColor(0, 0, 139)
	pdf.CellFormat(0, 6, fmt.Sprintf("Info: %d", severityCounts["info"]), "", 1, "L", false, 0, "")

	if severityCounts["unknown"] > 0 {
		pdf.SetTextColor(128, 128, 128)
		pdf.CellFormat(0, 6, fmt.Sprintf("Unknown: %d", severityCounts["unknown"]), "", 1, "L", false, 0, "")
	}

	pdf.SetTextColor(0, 0, 0)
	pdf.SetFont("Arial", "B", 10)
	pdf.CellFormat(0, 6, fmt.Sprintf("Total: %d", len(exporter.results)), "", 1, "L", false, 0, "")
}

// writeFindingsTable writes the findings table
func (exporter *Exporter) writeFindingsTable(pdf *gofpdf.Fpdf) {
	pdf.SetFont("Arial", "B", 14)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(0, 8, "Findings Overview", "", 1, "L", false, 0, "")
	pdf.Ln(2)

	// Table headers
	pdf.SetFont("Arial", "B", 9)
	pdf.SetFillColor(220, 220, 220)

	colWidths := []float64{20, 45, 45, 50, 25}
	headers := []string{"Severity", "Template", "Host", "Matched At", "Time"}

	for i, header := range headers {
		pdf.CellFormat(colWidths[i], 7, header, "1", 0, "C", true, 0, "")
	}
	pdf.Ln(-1)

	// Table rows
	pdf.SetFont("Arial", "", 8)
	pdf.SetFillColor(255, 255, 255)

	for _, result := range exporter.results {
		severity := result.Info.SeverityHolder.Severity.String()
		templateID := truncateString(result.TemplateID, 20)
		host := truncateString(result.Host, 20)
		matched := truncateString(result.Matched, 22)
		timestamp := result.Timestamp.Format("15:04:05")

		// Set severity color
		exporter.setSeverityColor(pdf, severity)
		pdf.CellFormat(colWidths[0], 6, severity, "1", 0, "C", false, 0, "")

		pdf.SetTextColor(0, 0, 0)
		pdf.CellFormat(colWidths[1], 6, templateID, "1", 0, "L", false, 0, "")
		pdf.CellFormat(colWidths[2], 6, host, "1", 0, "L", false, 0, "")
		pdf.CellFormat(colWidths[3], 6, matched, "1", 0, "L", false, 0, "")
		pdf.CellFormat(colWidths[4], 6, timestamp, "1", 0, "C", false, 0, "")
		pdf.Ln(-1)
	}
}

// writeDetailedFindings writes detailed information for each finding
func (exporter *Exporter) writeDetailedFindings(pdf *gofpdf.Fpdf) {
	pdf.SetFont("Arial", "B", 14)
	pdf.SetTextColor(0, 0, 0)
	pdf.CellFormat(0, 8, "Detailed Findings", "", 1, "L", false, 0, "")
	pdf.Ln(2)

	for i, result := range exporter.results {
		// Check if we need a new page
		if pdf.GetY() > 250 {
			pdf.AddPage()
		}

		severity := result.Info.SeverityHolder.Severity.String()

		// Finding header
		pdf.SetFont("Arial", "B", 11)
		exporter.setSeverityColor(pdf, severity)
		pdf.CellFormat(0, 7, fmt.Sprintf("[%d] %s - %s", i+1, result.Info.Name, severity), "", 1, "L", false, 0, "")

		pdf.SetTextColor(0, 0, 0)
		pdf.SetFont("Arial", "", 9)

		// Template info
		pdf.CellFormat(0, 5, fmt.Sprintf("Template: %s", result.TemplateID), "", 1, "L", false, 0, "")
		pdf.CellFormat(0, 5, fmt.Sprintf("Host: %s", result.Host), "", 1, "L", false, 0, "")

		if result.Matched != "" {
			pdf.CellFormat(0, 5, fmt.Sprintf("Matched At: %s", result.Matched), "", 1, "L", false, 0, "")
		}

		if result.URL != "" {
			pdf.CellFormat(0, 5, fmt.Sprintf("URL: %s", result.URL), "", 1, "L", false, 0, "")
		}

		if result.Info.Description != "" {
			pdf.Ln(2)
			pdf.SetFont("Arial", "I", 9)
			// Word wrap long descriptions
			description := truncateString(result.Info.Description, 500)
			pdf.MultiCell(0, 5, fmt.Sprintf("Description: %s", description), "", "L", false)
		}

		if len(result.ExtractedResults) > 0 {
			pdf.SetFont("Arial", "", 9)
			pdf.CellFormat(0, 5, fmt.Sprintf("Extracted: %s", strings.Join(result.ExtractedResults, ", ")), "", 1, "L", false, 0, "")
		}

		pdf.CellFormat(0, 5, fmt.Sprintf("Timestamp: %s", result.Timestamp.Format("2006-01-02 15:04:05")), "", 1, "L", false, 0, "")

		pdf.Ln(5)
	}
}

// setSeverityColor sets the text color based on severity
func (exporter *Exporter) setSeverityColor(pdf *gofpdf.Fpdf, severity string) {
	switch strings.ToLower(severity) {
	case "critical":
		pdf.SetTextColor(139, 0, 0)
	case "high":
		pdf.SetTextColor(255, 69, 0)
	case "medium":
		pdf.SetTextColor(255, 140, 0)
	case "low":
		pdf.SetTextColor(128, 128, 0)
	case "info":
		pdf.SetTextColor(0, 0, 139)
	default:
		pdf.SetTextColor(0, 0, 0)
	}
}

// truncateString truncates a string to a maximum length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
