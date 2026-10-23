package pdf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	fpdf "github.com/go-pdf/fpdf"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

const (
	defaultFile = "nuclei-report.pdf"
	maxRawLen   = 4096
)

// Options contains the configuration options for PDF exporter client.
type Options struct {
	// File is the file to export found results to in PDF format.
	File string `yaml:"file"`
	// OmitRaw omits request/response from the report.
	OmitRaw bool `yaml:"omit-raw"`
}

// Exporter is an exporter for nuclei PDF output format.
type Exporter struct {
	options *Options
	mu      sync.Mutex
	results []output.ResultEvent
}

// New creates a new PDF exporter integration client based on options.
func New(options *Options) (*Exporter, error) {
	opts := &Options{}
	if options != nil {
		*opts = *options
	}
	if opts.File == "" {
		opts.File = defaultFile
	}
	return &Exporter{
		options: opts,
		results: make([]output.ResultEvent, 0),
	}, nil
}

// Export appends a result event to the report buffer.
func (e *Exporter) Export(event *output.ResultEvent) error {
	if event == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	row := *event
	if e.options.OmitRaw {
		row.Request = ""
		row.Response = ""
	} else {
		if len(row.Request) > maxRawLen {
			row.Request = row.Request[:maxRawLen] + "\n[truncated]"
		}
		if len(row.Response) > maxRawLen {
			row.Response = row.Response[:maxRawLen] + "\n[truncated]"
		}
	}
	e.results = append(e.results, row)
	return nil
}

// Close generates the PDF report and writes it to disk.
// Returns nil without creating a file when there are no results.
func (e *Exporter) Close() error {
	e.mu.Lock()
	snapshot := make([]output.ResultEvent, len(e.results))
	copy(snapshot, e.results)
	opts := *e.options
	e.mu.Unlock()

	if len(snapshot) == 0 {
		return nil
	}
	if dir := filepath.Dir(opts.File); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return errors.Wrap(err, "could not create directory for PDF report")
		}
	}
	return generate(&opts, snapshot)
}

func generate(opts *Options, results []output.ResultEvent) error {
	doc := fpdf.New("P", "mm", "A4", "")
	doc.SetMargins(12, 15, 12)
	doc.SetAutoPageBreak(true, 18)
	renderHeader(doc)
	renderSummary(doc, results)
	renderFindings(doc, results)
	if err := doc.OutputFileAndClose(opts.File); err != nil {
		return errors.Wrap(err, "could not write PDF report")
	}
	return nil
}

func renderHeader(doc *fpdf.Fpdf) {
	doc.AddPage()
	doc.SetFont("Helvetica", "B", 18)
	doc.SetTextColor(30, 30, 30)
	doc.CellFormat(0, 10, "Nuclei Vulnerability Scan Report", "", 1, "C", false, 0, "")
	doc.SetFont("Helvetica", "", 9)
	doc.SetTextColor(100, 100, 100)
	doc.CellFormat(0, 5, "Generated: "+time.Now().UTC().Format("2006-01-02 15:04:05 UTC"), "", 1, "C", false, 0, "")
	doc.CellFormat(0, 5, "Engine: Nuclei "+config.Version, "", 1, "C", false, 0, "")
	doc.Ln(6)
}

type rgb struct{ r, g, b int }

var sevColors = map[string]rgb{
	"critical": {128, 0, 128},
	"high":     {200, 0, 0},
	"medium":   {200, 100, 0},
	"low":      {170, 140, 0},
	"info":     {0, 100, 180},
	"unknown":  {100, 100, 100},
}

var sevOrder = []string{"critical", "high", "medium", "low", "info", "unknown"}

func colorFor(sev string) (int, int, int) {
	if c, ok := sevColors[strings.ToLower(sev)]; ok {
		return c.r, c.g, c.b
	}
	return 100, 100, 100
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}

func renderSummary(doc *fpdf.Fpdf, results []output.ResultEvent) {
	counts := make(map[string]int, len(sevOrder))
	for _, r := range results {
		sev := strings.ToLower(r.Info.SeverityHolder.Severity.String())
		if _, ok := sevColors[sev]; ok {
			counts[sev]++
		} else {
			counts["unknown"]++
		}
	}
	doc.SetFont("Helvetica", "B", 11)
	doc.SetTextColor(30, 30, 30)
	doc.CellFormat(0, 7, fmt.Sprintf("Summary - %d finding(s)", len(results)), "", 1, "", false, 0, "")
	doc.Ln(1)
	colW := 28.0
	doc.SetFont("Helvetica", "B", 9)
	for _, sev := range sevOrder {
		r, g, b := colorFor(sev)
		doc.SetFillColor(r, g, b)
		doc.SetTextColor(255, 255, 255)
		doc.CellFormat(colW, 6, capitalize(sev), "1", 0, "C", true, 0, "")
	}
	doc.Ln(-1)
	doc.SetFont("Helvetica", "", 9)
	doc.SetFillColor(245, 245, 245)
	doc.SetTextColor(30, 30, 30)
	for _, sev := range sevOrder {
		doc.CellFormat(colW, 6, fmt.Sprintf("%d", counts[sev]), "1", 0, "C", true, 0, "")
	}
	doc.Ln(10)
}

func renderFindings(doc *fpdf.Fpdf, results []output.ResultEvent) {
	doc.SetFont("Helvetica", "B", 11)
	doc.SetTextColor(30, 30, 30)
	doc.CellFormat(0, 7, "Findings", "", 1, "", false, 0, "")
	doc.Ln(1)
	for i, r := range results {
		sev := strings.ToLower(r.Info.SeverityHolder.Severity.String())
		cr, cg, cb := colorFor(sev)
		doc.SetFont("Helvetica", "B", 10)
		doc.SetFillColor(cr, cg, cb)
		doc.SetTextColor(255, 255, 255)
		doc.CellFormat(0, 7, safeStr(fmt.Sprintf("[%s] %s", strings.ToUpper(sev), r.Info.Name)), "0", 1, "", true, 0, "")
		doc.SetFont("Helvetica", "", 9)
		doc.SetTextColor(30, 30, 30)
		doc.CellFormat(30, 5, "Host:", "0", 0, "", false, 0, "")
		doc.CellFormat(0, 5, safeStr(r.Host), "0", 1, "", false, 0, "")
		doc.CellFormat(30, 5, "Template:", "0", 0, "", false, 0, "")
		doc.CellFormat(0, 5, safeStr(r.TemplateID), "0", 1, "", false, 0, "")
		if r.Info.Description != "" {
			doc.SetFont("Helvetica", "I", 8)
			doc.SetTextColor(60, 60, 60)
			doc.MultiCell(0, 4, safeStr(r.Info.Description), "", "", false)
		}
		if r.Request != "" {
			renderCodeBlock(doc, "Request", r.Request)
		}
		if r.Response != "" {
			renderCodeBlock(doc, "Response", r.Response)
		}
		if i < len(results)-1 {
			doc.Ln(3)
			doc.SetDrawColor(200, 200, 200)
			doc.Line(12, doc.GetY(), 198, doc.GetY())
			doc.Ln(3)
		}
	}
}

func renderCodeBlock(doc *fpdf.Fpdf, label, content string) {
	doc.SetFont("Helvetica", "B", 8)
	doc.SetTextColor(60, 60, 60)
	doc.CellFormat(0, 5, label+":", "0", 1, "", false, 0, "")
	doc.SetFont("Courier", "", 7)
	doc.SetFillColor(240, 240, 240)
	doc.SetTextColor(40, 40, 40)
	doc.MultiCell(0, 4, safeStr(content), "1", "", true)
}

// safeStr replaces characters outside ISO-8859-1 with '?' for fpdf compatibility.
func safeStr(s string) string {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r > 255 {
			out = append(out, '?')
		} else {
			out = append(out, byte(r))
		}
	}
	return string(out)
}
