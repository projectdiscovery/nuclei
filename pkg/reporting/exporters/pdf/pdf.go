package pdf

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-pdf/fpdf"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// Options contains configuration options for PDF Exporter Module
type Options struct {
	// File is the file to export findings to
	File string `yaml:"file"`
}

// Exporter is an exporter for PDF file
type Exporter struct {
	options *Options
	mutex   *sync.Mutex
	data    []*output.ResultEvent
}

// New creates a new PDF exporter
func New(options *Options) (*Exporter, error) {
	return &Exporter{
		options: options,
		mutex:   &sync.Mutex{},
		data:    make([]*output.ResultEvent, 0),
	}, nil
}

// Export exports a result event to PDF
func (e *Exporter) Export(event *output.ResultEvent) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	e.data = append(e.data, event)
	return nil
}

// Close closes the exporter and writes the PDF file
func (e *Exporter) Close() error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(10, 15, 10)
	pdf.SetAutoPageBreak(true, 15)

	// --- Header & Footer ---
	pdf.SetHeaderFunc(func() {
		pdf.SetFont("Arial", "I", 8)
		pdf.SetTextColor(128, 128, 128)
		pdf.CellFormat(0, 10, fmt.Sprintf("Nuclei Scan Report - Generated: %s", time.Now().Format("2006-01-02 15:04:05")), "", 0, "R", false, 0, "")
		pdf.Ln(4)
	})
	pdf.SetFooterFunc(func() {
		pdf.SetY(-15)
		pdf.SetFont("Arial", "I", 8)
		pdf.SetTextColor(128, 128, 128)
		pdf.CellFormat(0, 10, fmt.Sprintf("Page %d", pdf.PageNo()), "", 0, "C", false, 0, "")
	})

	pdf.AddPage()

	// --- Title Page ---
	pdf.SetFont("Arial", "B", 24)
	pdf.SetTextColor(0, 0, 0)
	pdf.Cell(0, 20, "Nuclei Vulnerability Scan Report")
	pdf.Ln(20)

	if len(e.data) == 0 {
		pdf.SetFont("Arial", "", 12)
		pdf.Cell(0, 10, "No vulnerabilities found.")
		return pdf.OutputFileAndClose(e.options.File)
	}

	// --- Executive Summary ---
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 10, "Executive Summary")
	pdf.Ln(10)

	stats := make(map[string]int)
	for _, event := range e.data {
		stats[event.Info.SeverityHolder.Severity.String()]++
	}

	// Summary Table
	pdf.SetFont("Arial", "B", 10)
	pdf.SetFillColor(240, 240, 240)
	pdf.CellFormat(95, 8, "Severity", "1", 0, "L", true, 0, "")
	pdf.CellFormat(95, 8, "Count", "1", 1, "C", true, 0, "")

	pdf.SetFont("Arial", "", 10)
	severities := []string{"critical", "high", "medium", "low", "info", "unknown"}

	for _, sev := range severities {
		if count, ok := stats[sev]; ok && count > 0 {
			r, g, b := getSeverityColor(sev)
			pdf.SetTextColor(r, g, b)
			pdf.SetFont("Arial", "B", 10)
			pdf.CellFormat(95, 8, strings.ToUpper(sev), "1", 0, "L", false, 0, "")

			pdf.SetTextColor(0, 0, 0)
			pdf.SetFont("Arial", "", 10)
			pdf.CellFormat(95, 8, fmt.Sprintf("%d", count), "1", 1, "C", false, 0, "")
		}
	}
	pdf.Ln(10)

	// --- Detailed Findings ---
	pdf.SetFont("Arial", "B", 16)
	pdf.SetTextColor(0, 0, 0)
	pdf.Cell(0, 10, "Detailed Findings")
	pdf.Ln(10)

	// Sort findings by severity
	sort.Slice(e.data, func(i, j int) bool {
		return getSeverityWeight(e.data[i].Info.SeverityHolder.Severity.String()) > getSeverityWeight(e.data[j].Info.SeverityHolder.Severity.String())
	})

	for i, event := range e.data {
		// Avoid page break inside a finding block if possible. Estimate height?
		// Simple approach: Check Y position.
		if pdf.GetY() > 250 {
			pdf.AddPage()
		}

		// Finding Header
		r, g, b := getSeverityColor(event.Info.SeverityHolder.Severity.String())
		pdf.SetFillColor(r, g, b)
		pdf.SetTextColor(255, 255, 255)
		pdf.SetFont("Arial", "B", 11)

		title := fmt.Sprintf("#%d [%s] %s", i+1, strings.ToUpper(event.Info.SeverityHolder.Severity.String()), event.TemplateID)
		pdf.CellFormat(0, 8, title, "0", 1, "L", true, 0, "")

		// Finding Details
		pdf.SetTextColor(0, 0, 0)
		pdf.SetFont("Arial", "", 10)

		// Host & URL
		pdf.SetFont("Arial", "B", 10)
		pdf.Cell(20, 6, "Host:")
		pdf.SetFont("Arial", "", 10)
		pdf.Cell(0, 6, event.Host)
		pdf.Ln(6)

		pdf.SetFont("Arial", "B", 10)
		pdf.Cell(20, 6, "URL:")
		pdf.SetFont("Arial", "", 10)
		pdf.MultiCell(0, 6, event.URL, "", "L", false) // URL might wrap

		// Description (if any)
		if event.Info.Description != "" {
			pdf.SetFont("Arial", "B", 10)
			pdf.Cell(0, 6, "Description:")
			pdf.Ln(6)
			pdf.SetFont("Arial", "", 10)
			pdf.MultiCell(0, 5, event.Info.Description, "", "L", false)
		}

		// Extracted Results (if any)
		if len(event.ExtractedResults) > 0 {
			pdf.Ln(2)
			pdf.SetFont("Arial", "B", 10)
			pdf.Cell(0, 6, "Extracted Data:")
			pdf.Ln(6)
			pdf.SetFont("Courier", "", 9) // Monospace for data
			pdf.MultiCell(0, 5, strings.Join(event.ExtractedResults, "\n"), "1", "L", false)
		}

		pdf.Ln(8)
	}

	return pdf.OutputFileAndClose(e.options.File)
}

func getSeverityColor(sev string) (int, int, int) {
	switch strings.ToLower(sev) {
	case "critical":
		return 156, 39, 176 // Purple/Redish
	case "high":
		return 244, 67, 54 // Red
	case "medium":
		return 255, 152, 0 // Orange
	case "low":
		return 255, 235, 59 // Yellow
	case "info":
		return 33, 150, 243 // Blue
	default:
		return 158, 158, 158 // Grey
	}
}

func getSeverityWeight(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}
