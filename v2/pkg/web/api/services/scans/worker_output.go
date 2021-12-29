package scans

import (
	"bufio"
	"context"
	"database/sql"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/format"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
)

type wrappedOutputWriter struct {
	db         dbsql.Querier
	scanid     int64
	scanSource string
	logs       *bufio.Writer
	colorizer  aurora.Aurora
}

func newWrappedOutputWriter(db dbsql.Querier, logWriter *bufio.Writer, scanid int64, scanSource string) *wrappedOutputWriter {
	return &wrappedOutputWriter{
		db:         db,
		scanid:     scanid,
		scanSource: scanSource,
		logs:       logWriter,
		colorizer:  aurora.NewAurora(false),
	}
}

// Close closes the output writer interface
func (w *wrappedOutputWriter) Close() {}

// Colorizer returns the colorizer instance for writer
func (w *wrappedOutputWriter) Colorizer() aurora.Aurora {
	return w.colorizer
}

// Write writes the event to file and/or screen.
func (w *wrappedOutputWriter) Write(event *output.ResultEvent) error {
	contents, err := ioutil.ReadFile(event.TemplatePath)
	if err != nil {
		return err
	}

	description := event.Info.Name
	if event.Info.Description != "" {
		description = event.Info.Description
	}
	var cweids []int32
	var cvss float64
	if event.Info.Classification != nil {
		cvss = event.Info.Classification.CVSSScore
		cweids = convertCWEIDsToSlice(event.Info.Classification.CWEID)
	}
	_, err = w.db.AddIssue(context.Background(), dbsql.AddIssueParams{
		Matchedat:     event.Matched,
		Title:         format.Summary(event),
		Severity:      event.Info.SeverityHolder.Severity.String(),
		Scansource:    w.scanSource,
		Issuestate:    "open",
		Description:   description,
		Author:        event.Info.Authors.String(),
		Cvss:          sql.NullFloat64{Float64: cvss, Valid: true},
		Cwe:           cweids,
		Labels:        event.Info.Tags.ToSlice(),
		Issuedata:     format.MarkdownDescription(event),
		Issuetemplate: string(contents),
		Templatename:  filepath.Base(event.TemplatePath),
		Hash:          event.Hash(),
		Remediation:   sql.NullString{String: event.Info.Remediation, Valid: true},
		Scanid:        w.scanid,
	})
	return err
}

// WriteFailure writes the optional failure event for template to file and/or screen.
func (w *wrappedOutputWriter) WriteFailure(event output.InternalEvent) error {
	return nil
}

// ScanErrorLogEvent is a log event for scan error log
type ScanErrorLogEvent struct {
	Template string `json:"template"`
	URL      string `json:"url"`
	Type     string `json:"type"`
	Error    string `json:"error"`
}

// Request logs a request in the trace log
func (w *wrappedOutputWriter) Request(templateID, url, requestType string, err error) {
	if err == nil {
		return
	}
	_ = jsoniter.NewEncoder(w.logs).Encode(ScanErrorLogEvent{
		Template: templateID,
		URL:      url,
		Type:     requestType,
		Error:    err.Error(),
	})
}

func convertCWEIDsToSlice(cweIDs stringslice.StringSlice) []int32 {
	values := make([]int32, len(cweIDs.ToSlice()))
	for i, value := range cweIDs.ToSlice() {
		parts := strings.SplitN(value, "-", 2)
		if len(parts) < 2 {
			continue
		}
		parsed, _ := strconv.ParseInt(parts[1], 10, 32)
		values[i] = int32(parsed)
	}
	return values
}
