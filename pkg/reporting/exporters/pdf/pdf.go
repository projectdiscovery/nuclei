package pdf

import (
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"codeberg.org/go-pdf/fpdf"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

const (
	maxContentLength = 2000
	maxExtractedLen  = 200
)

type Exporter struct {
	options *Options
	mutex   *sync.Mutex
	rows    []output.ResultEvent
}

type Options struct {
	File    string `yaml:"file"`
	OmitRaw bool   `yaml:"omit-raw"`
}

func New(options *Options) (*Exporter, error) {
	exporter := &Exporter{
		mutex:   &sync.Mutex{},
		options: options,
		rows:    []output.ResultEvent{},
	}
	return exporter, nil
}

func (exporter *Exporter) Export(event *output.ResultEvent) error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	if exporter.options.OmitRaw {
		event.Request = ""
		event.Response = ""
	}

	exporter.rows = append(exporter.rows, *event)

	return nil
}

func (exporter *Exporter) Close() error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	if len(exporter.rows) == 0 {
		return nil
	}

	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(10, 10, 10)
	pdf.SetAutoPageBreak(true, 10)

	pdf.AddPage()
	pdf.SetFont("Arial", "B", 24)
	pdf.CellFormat(0, 20, "Nuclei Scan Report", "", 1, "C", false, 0, "")

	pdf.SetFont("Arial", "", 12)
	pdf.CellFormat(0, 10, fmt.Sprintf("Generated: %s", time.Now().Format("2006-01-02 15:04:05")), "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 10, fmt.Sprintf("Total Findings: %d", len(exporter.rows)), "", 1, "C", false, 0, "")
	pdf.Ln(10)

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
			pdf.CellFormat(0, 7, fmt.Sprintf("  %s: %d", capitalize(severity), count), "", 1, "L", false, 0, "")
		}
	}
	pdf.Ln(5)

	pdf.AddPage()
	pdf.SetFont("Arial", "B", 16)
	pdf.CellFormat(0, 10, "Detailed Findings", "", 1, "L", false, 0, "")
	pdf.Ln(5)

	for i, event := range exporter.rows {
		if i > 0 {
			pdf.AddPage()
		}

		pdf.SetFont("Arial", "B", 14)

		severity := "unknown"
		if event.Info.SeverityHolder.Severity != 0 {
			severity = event.Info.SeverityHolder.Severity.String()
		}

		switch severity {
		case "critical":
			pdf.SetFillColor(139, 0, 0)
			pdf.SetTextColor(255, 255, 255)
		case "high":
			pdf.SetFillColor(255, 0, 0)
			pdf.SetTextColor(255, 255, 255)
		case "medium":
			pdf.SetFillColor(255, 165, 0)
			pdf.SetTextColor(0, 0, 0)
		case "low":
			pdf.SetFillColor(255, 255, 0)
			pdf.SetTextColor(0, 0, 0)
		case "info":
			pdf.SetFillColor(0, 191, 255)
			pdf.SetTextColor(0, 0, 0)
		default:
			pdf.SetFillColor(128, 128, 128)
			pdf.SetTextColor(255, 255, 255)
		}

		pdf.CellFormat(0, 10, fmt.Sprintf("Finding #%d - %s", i+1, strings.ToUpper(severity)), "", 1, "C", true, 0, "")
		pdf.SetTextColor(0, 0, 0)
		pdf.Ln(3)

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

		if len(event.ExtractedResults) > 0 {
			pdf.SetFont("Arial", "B", 11)
			pdf.Cell(35, 7, "Extracted:")
			pdf.SetFont("Arial", "", 11)
			extracted := strings.Join(event.ExtractedResults, ", ")
			if len(extracted) > maxExtractedLen {
				extracted = extracted[:maxExtractedLen] + "..."
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

		if event.Info.Description != "" {
			pdf.Ln(3)
			pdf.SetFont("Arial", "B", 11)
			pdf.Cell(0, 7, "Description:")
			pdf.Ln(5)
			pdf.SetFont("Arial", "", 10)
			pdf.MultiCell(0, 5, event.Info.Description, "", "L", false)
		}

		if len(event.Info.Tags.ToSlice()) > 0 {
			pdf.Ln(3)
			pdf.SetFont("Arial", "B", 11)
			pdf.Cell(0, 7, "Tags:")
			pdf.Ln(5)
			pdf.SetFont("Arial", "", 10)
			pdf.MultiCell(0, 5, strings.Join(event.Info.Tags.ToSlice(), ", "), "", "L", false)
		}

		if !exporter.options.OmitRaw {
			if event.Request != "" {
				pdf.Ln(3)
				pdf.SetFont("Arial", "B", 11)
				pdf.Cell(0, 7, "Request:")
				pdf.Ln(5)
				pdf.SetFont("Courier", "", 8)
				request := sanitizeContent(event.Request, maxContentLength)
				pdf.MultiCell(0, 4, request, "", "L", false)
			}

			if event.Response != "" {
				pdf.Ln(3)
				pdf.SetFont("Arial", "B", 11)
				pdf.Cell(0, 7, "Response:")
				pdf.Ln(5)
				pdf.SetFont("Courier", "", 8)
				response := sanitizeContent(event.Response, maxContentLength)
				pdf.MultiCell(0, 4, response, "", "L", false)
			}
		}

		func() {
			defer func() {
				recover()
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

	err := pdf.OutputFileAndClose(exporter.options.File)
	if err != nil {
		return errors.Wrap(err, "failed to create PDF file")
	}

	return nil
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

func sanitizeContent(content string, maxLen int) string {
	content = strings.ReplaceAll(content, "\x00", "")
	if len(content) > maxLen {
		return content[:maxLen] + "\n... (truncated)"
	}
	return content
}
