package scans

import (
	"context"
	"database/sql"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v2/pkg/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/format"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/settings"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
	"go.uber.org/ratelimit"
	"gopkg.in/yaml.v3"
)

type percentReturnFunc func() float64

func makePercentReturnFunc(stats progress.Progress) percentReturnFunc {
	return percentReturnFunc(func() float64 {
		return stats.Percent()
	})
}

// worker is a worker for executing a scan request
func (s *ScanService) worker(req ScanRequest) error {
	setting, err := s.db.Queries().GetSettingByName(context.Background(), sql.NullString{String: req.Config, Valid: true})
	if err != nil {
		return err
	}
	settings := &settings.Settings{}
	if yamlErr := yaml.NewDecoder(strings.NewReader(setting.Settingdata.String)).Decode(settings); yamlErr != nil {
		return yamlErr
	}
	typesOptions := settings.ToTypesOptions()

	templatesDirectory, templatesList, workflowsList, err := s.storeTemplatesFromRequest(req.Templates)
	if err != nil {
		return err
	}
	defer os.RemoveAll(templatesDirectory)

	typesOptions.TemplatesDirectory = templatesDirectory
	typesOptions.Templates = templatesList
	typesOptions.Workflows = workflowsList

	progressImpl, _ := progress.NewStatsTicker(0, false, false, false, 0)
	s.running.Store(req.ScanID, makePercentReturnFunc(progressImpl))
	defer func() {
		s.running.Delete(req.ScanID)

		// todo: Mark scan state as finished
	}()

	executerOpts := protocols.ExecuterOptions{
		Output:       newWrappedOutputWriter(s.db, req.ScanID),
		IssuesClient: nil, //todo: load from config value
		Options:      typesOptions,
		Progress:     progressImpl,
		Catalog:      catalog.New(templatesDirectory),
		RateLimiter:  ratelimit.New(typesOptions.RateLimit),
	}
	if typesOptions.RateLimitMinute > 0 {
		executerOpts.RateLimiter = ratelimit.New(typesOptions.RateLimitMinute, ratelimit.Per(60*time.Second))
	} else {
		executerOpts.RateLimiter = ratelimit.New(typesOptions.RateLimit)
	}

	store, err := loader.New(loader.NewConfig(typesOptions, catalog.New(templatesDirectory), executerOpts))
	if err != nil {
		return err
	}
	store.Load()

	executer := core.New(typesOptions)
	executer.SetExecuterOptions(executerOpts)

	workflowLoader, err := parsers.NewLoader(&executerOpts)
	if err != nil {
		return err
	}
	executerOpts.WorkflowLoader = workflowLoader

	var finalTemplates []*templates.Template
	finalTemplates = append(finalTemplates, store.Templates()...)
	finalTemplates = append(finalTemplates, store.Workflows()...)

	inputProvider, err := s.inputProviderFromRequest(req.Targets)
	if err != nil {
		return err
	}
	_ = executer.Execute(finalTemplates, inputProvider)
	log.Printf("Finish scan for ID: %d\n", req.ScanID)
	return nil
}

// inputProviderFromRequest returns an input provider from scan request
func (s *ScanService) inputProviderFromRequest(inputsList []string) (core.InputProvider, error) {
	tempfile, err := ioutil.TempFile("", "nuclei-input-*")
	if err != nil {
		return nil, err
	}
	defer tempfile.Close()

	for _, input := range inputsList {
		parsedID, err := strconv.ParseInt(input, 10, 64)
		if err != nil {
			_, _ = tempfile.WriteString(input)
			_, _ = tempfile.WriteString("\n")
		} else {
			target, err := s.db.Queries().GetTarget(context.Background(), parsedID)
			if err != nil {
				return nil, err
			}
			read, err := s.target.Read(target.Internalid.String)
			if err != nil {
				return nil, err
			}
			_, _ = io.Copy(tempfile, read)
			_ = read.Close()
		}
	}
	return &inputs.FileInputProvider{Path: tempfile.Name()}, nil
}

// storeTemplatesFromRequest writes templates from db to a temporary
// on disk directory for the duration of the scan.
func (s *ScanService) storeTemplatesFromRequest(templatesList []string) (string, []string, []string, error) {
	directory, err := ioutil.TempDir("", "nuclei-templates-*")
	if err != nil {
		return "", nil, nil, err
	}
	var templates, workflows []string
	for _, template := range templatesList {
		resp, err := s.db.Queries().GetTemplatesForScan(context.Background(), sql.NullString{String: template, Valid: true})
		if err != nil {
			return "", nil, nil, err
		}

		for _, value := range resp {
			if strings.Contains(value.Contents, "workflow:") {
				workflows = append(workflows, value.Path)
			} else {
				templates = append(templates, value.Path)
			}
			directoryBase := filepath.Dir(value.Path)
			_ = os.MkdirAll(path.Join(directory, directoryBase), os.ModePerm)

			if err = ioutil.WriteFile(path.Join(directory, value.Path), []byte(value.Contents), os.ModePerm); err != nil {
				return "", nil, nil, err
			}
		}
	}
	return directory, templates, workflows, nil
}

type wrappedOutputWriter struct {
	db        *db.Database
	scanid    int64
	colorizer aurora.Aurora
}

func newWrappedOutputWriter(db *db.Database, scanid int64) *wrappedOutputWriter {
	return &wrappedOutputWriter{db: db, colorizer: aurora.NewAurora(false)}
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
	// TODO: deduplicate issues before writing to db
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
	err = w.db.Queries().AddIssue(context.Background(), dbsql.AddIssueParams{
		Matchedat:     sql.NullString{String: event.Matched, Valid: true},
		Title:         sql.NullString{String: format.Summary(event), Valid: true},
		Severity:      sql.NullString{String: event.Info.SeverityHolder.Severity.String(), Valid: true},
		Scansource:    sql.NullString{String: event.Matched, Valid: true},
		Issuestate:    sql.NullString{String: "open", Valid: true},
		Description:   sql.NullString{String: description, Valid: true},
		Author:        sql.NullString{String: event.Info.Authors.String(), Valid: true},
		Cvss:          sql.NullFloat64{Float64: cvss, Valid: true},
		Cwe:           cweids,
		Labels:        event.Info.Tags.ToSlice(),
		Issuedata:     sql.NullString{String: format.MarkdownDescription(event), Valid: true},
		Issuetemplate: sql.NullString{String: string(contents), Valid: true},
		Remediation:   sql.NullString{String: event.Info.Remediation, Valid: true},
		Scanid:        sql.NullInt64{Int64: w.scanid, Valid: true},
	})
	return err
}

// WriteFailure writes the optional failure event for template to file and/or screen.
func (w *wrappedOutputWriter) WriteFailure(event output.InternalEvent) error {
	return nil
}

// Request logs a request in the trace log
func (w *wrappedOutputWriter) Request(templateID, url, requestType string, err error) {
	// todo: write somewhere scan error log

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
