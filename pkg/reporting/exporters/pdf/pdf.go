package pdf

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jung-kurt/gofpdf"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

type Exporter struct {
	options *Options
	mutex   *sync.Mutex
	rows    []output.ResultEvent
}

// Options contains the configuration options for PDF exporter client
type Options struct {
	// File is the file to export found PDF result to
	File    string `yaml:"file"`
	OmitRaw bool   `yaml:"omit-raw"`
}

// New creates a new PDF exporter integration client based on options.
func New(options *Options) (*Exporter, error) {
	exporter := &Exporter{
		mutex:   &sync.Mutex{},
		options: options,
		rows:    []output.ResultEvent{},
	}
	return exporter, nil
}

// Export appends the passed result event to the list of objects to be exported to
// the resulting PDF file
func (exporter *Exporter) Export(event *output.ResultEvent) error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	if exporter.options.OmitRaw {
		event.Request = ""
		event.Response = ""
	}

	// Add the event to the rows
	exporter.rows = append(exporter.rows, *event)

	return nil
}

// Close writes the in-memory data to the PDF file specified by options and closes
// the exporter after operation
func (exporter *Exporter) Close() error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	if len(exporter.rows) == 0 {
		return nil
	}

	// Create a new PDF
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(10, 10, 10)
	pdf.SetAutoPageBreak(true, 10)

	// Add first page
	pdf.AddPage()

	// Title page
	pdf.SetFont("Arial", "B", 24)
	pdf.CellFormat(0, 20, "Nuclei Scan Report", "", 1, "C", false, 0, "")
	
	pdf.SetFont("Arial", "", 12)
	pdf.CellFormat(0, 10, fmt.Sprintf("Generated: %s", time.Now().Format("2006-01-02 15:04:05")), "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 10, fmt.Sprintf("Total Findings: %d", len(exporter.rows)), "", 1, "C", false, 0, "")
	pdf.Ln(10)

	// Summary by severity
	severityCount := make(map[string]int)
	for _, event := range exporter.rows {
		severity := "unknown"
		if event.Info.SeverityHolder.Severity != 0 {
			severity = event.Info.SeverityHolder.Severity.String()
		}
		severityCount[severity]++
	}

	pdf.SetFont("Arial", "B", 14)
	pdf.CellFormat(0, 10, "Summary by Severity", "", 1, "L", false, 0, "")
	pdf.SetFont("Arial", "", 11)
	
	for _, severity := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		if count, exists := severityCount[severity]; exists && count > 0 {
			pdf.CellFormat(0, 7, fmt.Sprintf("  %s: %d", strings.Title(severity), count), "", 1, "L", false, 0, "")
		}
	}
	pdf.Ln(5)

	// Detailed findings
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 16)
	pdf.CellFormat(0, 10, "Detailed Findings", "", 1, "L", false, 0, "")
	pdf.Ln(5)

	for i, event := range exporter.rows {
		// Add new page for each finding (except the first)
		if i > 0 {
			pdf.AddPage()
		}

		// Finding header with colored background based on severity
		pdf.SetFont("Arial", "B", 14)
		
		severity := "unknown"
		if event.Info.SeverityHolder.Severity != 0 {
			severity = event.Info.SeverityHolder.Severity.String()
		}
		
		// Set color based on severity
		switch severity {
		case "critical":
			pdf.SetFillColor(139, 0, 0) // Dark red
			pdf.SetTextColor(255, 255, 255)
		case "high":
			pdf.SetFillColor(255, 0, 0) // Red
			pdf.SetTextColor(255, 255, 255)
		case "medium":
			pdf.SetFillColor(255, 165, 0) // Orange
			pdf.SetTextColor(0, 0, 0)
		case "low":
			pdf.SetFillColor(255, 255, 0) // Yellow
			pdf.SetTextColor(0, 0, 0)
		case "info":
			pdf.SetFillColor(0, 191, 255) // Light blue
			pdf.SetTextColor(0, 0, 0)
		default:
			pdf.SetFillColor(128, 128, 128) // Gray
			pdf.SetTextColor(255, 255, 255)
		}
		
		pdf.CellFormat(0, 10, fmt.Sprintf("Finding #%d - %s", i+1, strings.ToUpper(severity)), "", 1, "C", true, 0, "")
		pdf.SetTextColor(0, 0, 0)
		pdf.Ln(3)

		// Finding details
		pdf.SetFont("Arial", "B", 11)
		pdf.Cell(35, 7, "Template ID:")
		pdf.SetFont("Arial", "", 11)
		pdf.MultiCell(0, 7, event.TemplateID, "", "L", false)

		pdf.SetFont("Arial", "B", 11)
		pdf.Cell(35, 7, "Template:")
		pdf.SetFont("Arial", "", 11)
		pdf.MultiCell(0, 7, event.Info.Name, "", "L", false)

		pdf.SetFont("Arial", "B", 11)
		pdf.Cell(35, 7, "Host:")
		pdf.SetFont("Arial", "", 11)
		pdf.MultiCell(0, 7, event.Host, "", "L", false)

		pdf.SetFont("Arial", "B", 11)
		pdf.Cell(35, 7, "Matched:")
		pdf.SetFont("Arial", "", 11)
		pdf.MultiCell(0, 7, event.Matched, "", "L", false)

		if event.ExtractedResults != nil && len(event.ExtractedResults) > 0 {
			pdf.SetFont("Arial", "B", 11)
			pdf.Cell(35, 7, "Extracted:")
			pdf.SetFont("Arial", "", 11)
			extracted := strings.Join(event.ExtractedResults, ", ")
			if len(extracted) > 200 {
				extracted = extracted[:200] + "..."
			}
			pdf.MultiCell(0, 7, extracted, "", "L", false)
		}

		if event.IP != "" {
			pdf.SetFont("Arial", "B", 11)
			pdf.Cell(35, 7, "IP Address:")
			pdf.SetFont("Arial", "", 11)
			pdf.MultiCell(0, 7, event.IP, "", "L", false)
		}

		if event.Type != "" {
			pdf.SetFont("Arial", "B", 11)
			pdf.Cell(35, 7, "Type:")
			pdf.SetFont("Arial", "", 11)
			pdf.MultiCell(0, 7, event.Type, "", "L", false)
		}

		// Description
		if event.Info.Description != "" {
			pdf.Ln(3)
			pdf.SetFont("Arial", "B", 11)
			pdf.Cell(0, 7, "Description:")
			pdf.Ln(5)
			pdf.SetFont("Arial", "", 10)
			pdf.MultiCell(0, 5, event.Info.Description, "", "L", false)
		}

		// Tags
		if len(event.Info.Tags.ToSlice()) > 0 {
			pdf.Ln(3)
			pdf.SetFont("Arial", "B", 11)
			pdf.Cell(0, 7, "Tags:")
			pdf.Ln(5)
			pdf.SetFont("Arial", "", 10)
			pdf.MultiCell(0, 5, strings.Join(event.Info.Tags.ToSlice(), ", "), "", "L", false)
		}

		// Request/Response if not omitted
		if !exporter.options.OmitRaw {
			if event.Request != "" {
				pdf.Ln(3)
				pdf.SetFont("Arial", "B", 11)
				pdf.Cell(0, 7, "Request:")
				pdf.Ln(5)
				pdf.SetFont("Courier", "", 8)
				// Truncate if too long
				request := event.Request
				if len(request) > 2000 {
					request = request[:2000] + "\n... (truncated)"
				}
				// Clean the request from any problematic characters
				request = strings.ReplaceAll(request, "\x00", "")
				pdf.MultiCell(0, 4, request, "", "L", false)
			}

			if event.Response != "" {
				pdf.Ln(3)
				pdf.SetFont("Arial", "B", 11)
				pdf.Cell(0, 7, "Response:")
				pdf.Ln(5)
				pdf.SetFont("Courier", "", 8)
				// Truncate if too long
				response := event.Response
				if len(response) > 2000 {
					response = response[:2000] + "\n... (truncated)"
				}
				// Clean the response from any problematic characters
				response = strings.ReplaceAll(response, "\x00", "")
				pdf.MultiCell(0, 4, response, "", "L", false)
			}
		}

		// Reference - use defer/recover to handle any panics from StringSlice
		func() {
			defer func() {
				if r := recover(); r != nil {
					// Silently skip if Reference field causes issues
				}
			}()
			refSlice := event.Info.Reference.ToSlice()
			if len(refSlice) > 0 {
				pdf.Ln(3)
				pdf.SetFont("Arial", "B", 11)
				pdf.Cell(0, 7, "References:")
				pdf.Ln(5)
				pdf.SetFont("Arial", "", 9)
				for _, ref := range refSlice {
					pdf.MultiCell(0, 5, "- "+ref, "", "L", false)
				}
			}
		}()

		pdf.Ln(5)
	}

	// Save the PDF
	err := pdf.OutputFileAndClose(exporter.options.File)
	if err != nil {
		return errors.Wrap(err, "failed to create PDF file")
	}

	return nil
}
