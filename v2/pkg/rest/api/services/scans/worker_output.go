package scans

import (
	"bufio"
	"context"
	"database/sql"
	"path/filepath"
	"strconv"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/format"
	"github.com/projectdiscovery/nuclei/v2/pkg/rest/db/dbsql"
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
	description := event.Info.Name
	if event.Info.Description != "" {
		description = event.Info.Description
	}
	var cvssmetrics string
	var cveid string
	var cweids []int32
	var cvss float64
	if event.Info.Classification != nil {
		cvss = event.Info.Classification.CVSSScore
		cveid = event.Info.Classification.CVEID.String()
		cvssmetrics = event.Info.Classification.CVSSMetrics
		cweids = convertCWEIDsToSlice(event.Info.Classification.CWEID)
	}
	var metadata string
	if len(event.Metadata) > 0 {
		data, _ := jsoniter.Marshal(event.Metadata)
		metadata = string(data)
	}
	var interaction string
	if event.Interaction != nil {
		data, _ := jsoniter.Marshal(event.Interaction)
		interaction = string(data)
	}
	_, err := w.db.AddIssue(context.Background(), dbsql.AddIssueParams{
		Template:         event.Template,
		Templateurl:      sql.NullString{String: event.TemplateURL, Valid: true},
		Templateid:       sql.NullString{String: event.TemplateID, Valid: true},
		Templatepath:     sql.NullString{String: event.TemplatePath, Valid: true},
		Templatename:     filepath.Base(event.TemplatePath),
		Author:           sql.NullString{String: event.Info.Authors.String(), Valid: true},
		Description:      description,
		Reference:        event.Info.Reference.ToSlice(),
		Severity:         event.Info.SeverityHolder.Severity.String(),
		Templatemetadata: sql.NullString{String: event.Path, Valid: true},
		Cveid:            sql.NullString{String: cveid, Valid: true},
		Cvssmetrics:      sql.NullString{String: cvssmetrics, Valid: true},
		Matchername:      sql.NullString{String: event.MatcherName, Valid: true},
		Extractorname:    sql.NullString{String: event.MatcherName, Valid: true},
		Resulttype:       event.Type,
		Host:             event.Host,
		Path:             sql.NullString{String: event.Path, Valid: true},
		Extractedresults: event.ExtractedResults,
		Request:          sql.NullString{String: event.Request, Valid: true},
		Response:         sql.NullString{String: event.Response, Valid: true},
		Metadata:         sql.NullString{String: metadata, Valid: true},
		Ip:               sql.NullString{String: event.IP, Valid: true},
		Interaction:      sql.NullString{String: interaction, Valid: true},
		Curlcommand:      sql.NullString{String: event.CURLCommand, Valid: true},
		Matcherstatus:    sql.NullBool{Bool: event.MatcherStatus, Valid: true},
		Scanid:           w.scanid,
		Matchedat:        event.Matched,
		Title:            format.Summary(event),
		Scansource:       w.scanSource,
		Issuestate:       "open",
		Cvss:             sql.NullFloat64{Float64: cvss, Valid: true},
		Cwe:              cweids,
		Labels:           event.Info.Tags.ToSlice(),
		Hash:             event.Hash(),
		Remediation:      sql.NullString{String: event.Info.Remediation, Valid: true},
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
