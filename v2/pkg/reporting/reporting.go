package reporting

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"gopkg.in/yaml.v2"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/dedupe"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/exporters/es"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/exporters/markdown"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/exporters/sarif"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/trackers/github"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/trackers/gitlab"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/trackers/jira"
	"github.com/projectdiscovery/retryablehttp-go"
	fileutil "github.com/projectdiscovery/utils/file"
)

// Options is a configuration file for nuclei reporting module
type Options struct {
	// AllowList contains a list of allowed events for reporting module
	AllowList *Filter `yaml:"allow-list"`
	// DenyList contains a list of denied events for reporting module
	DenyList *Filter `yaml:"deny-list"`
	// GitHub contains configuration options for GitHub Issue Tracker
	GitHub *github.Options `yaml:"github"`
	// GitLab contains configuration options for GitLab Issue Tracker
	GitLab *gitlab.Options `yaml:"gitlab"`
	// Jira contains configuration options for Jira Issue Tracker
	Jira *jira.Options `yaml:"jira"`
	// MarkdownExporter contains configuration options for Markdown Exporter Module
	MarkdownExporter *markdown.Options `yaml:"markdown"`
	// SarifExporter contains configuration options for Sarif Exporter Module
	SarifExporter *sarif.Options `yaml:"sarif"`
	// ElasticsearchExporter contains configuration options for Elasticsearch Exporter Module
	ElasticsearchExporter *es.Options `yaml:"elasticsearch"`

	HttpClient *retryablehttp.Client `yaml:"-"`
}

// Filter filters the received event and decides whether to perform
// reporting for it or not.
type Filter struct {
	Severities severity.Severities     `yaml:"severity"`
	Tags       stringslice.StringSlice `yaml:"tags"`
}

const (
	reportingClientCreationErrorMessage = "could not create reporting client"
	exportClientCreationErrorMessage    = "could not create exporting client"
)

// GetMatch returns true if a filter matches result event
func (filter *Filter) GetMatch(event *output.ResultEvent) bool {
	return isSeverityMatch(event, filter) && isTagMatch(event, filter) // TODO revisit this
}

func isTagMatch(event *output.ResultEvent, filter *Filter) bool {
	filterTags := filter.Tags
	if filterTags.IsEmpty() {
		return true
	}

	tags := event.Info.Tags.ToSlice()
	for _, tag := range filterTags.ToSlice() {
		if stringSliceContains(tags, tag) {
			return true
		}
	}

	return false
}

func isSeverityMatch(event *output.ResultEvent, filter *Filter) bool {
	resultEventSeverity := event.Info.SeverityHolder.Severity // TODO review

	if len(filter.Severities) == 0 {
		return true
	}

	for _, current := range filter.Severities {
		if current == resultEventSeverity {
			return true
		}
	}

	return false
}

// Tracker is an interface implemented by an issue tracker
type Tracker interface {
	// CreateIssue creates an issue in the tracker
	CreateIssue(event *output.ResultEvent) error
}

// Exporter is an interface implemented by an issue exporter
type Exporter interface {
	// Close closes the exporter after operation
	Close() error
	// Export exports an issue to an exporter
	Export(event *output.ResultEvent) error
}

// Client is a client for nuclei issue tracking module
type Client struct {
	trackers  []Tracker
	exporters []Exporter
	options   *Options
	dedupe    *dedupe.Storage
}

// New creates a new nuclei issue tracker reporting client
func New(options *Options, db string) (*Client, error) {
	client := &Client{options: options}

	if options.GitHub != nil {
		options.GitHub.HttpClient = options.HttpClient
		tracker, err := github.New(options.GitHub)
		if err != nil {
			return nil, errors.Wrap(err, reportingClientCreationErrorMessage)
		}
		client.trackers = append(client.trackers, tracker)
	}
	if options.GitLab != nil {
		options.GitLab.HttpClient = options.HttpClient
		tracker, err := gitlab.New(options.GitLab)
		if err != nil {
			return nil, errors.Wrap(err, reportingClientCreationErrorMessage)
		}
		client.trackers = append(client.trackers, tracker)
	}
	if options.Jira != nil {
		options.Jira.HttpClient = options.HttpClient
		tracker, err := jira.New(options.Jira)
		if err != nil {
			return nil, errors.Wrap(err, reportingClientCreationErrorMessage)
		}
		client.trackers = append(client.trackers, tracker)
	}
	if options.MarkdownExporter != nil {
		exporter, err := markdown.New(options.MarkdownExporter)
		if err != nil {
			return nil, errors.Wrap(err, exportClientCreationErrorMessage)
		}
		client.exporters = append(client.exporters, exporter)
	}
	if options.SarifExporter != nil {
		exporter, err := sarif.New(options.SarifExporter)
		if err != nil {
			return nil, errors.Wrap(err, exportClientCreationErrorMessage)
		}
		client.exporters = append(client.exporters, exporter)
	}
	if options.ElasticsearchExporter != nil {
		options.ElasticsearchExporter.HttpClient = options.HttpClient
		exporter, err := es.New(options.ElasticsearchExporter)
		if err != nil {
			return nil, errors.Wrap(err, exportClientCreationErrorMessage)
		}
		client.exporters = append(client.exporters, exporter)
	}

	storage, err := dedupe.New(db)
	if err != nil {
		return nil, err
	}
	client.dedupe = storage
	return client, nil
}

// CreateConfigIfNotExists creates report-config if it doesn't exists
func CreateConfigIfNotExists() error {
	config, err := config.GetConfigDir()
	if err != nil {
		return errors.Wrap(err, "could not get config directory")
	}
	reportingConfig := filepath.Join(config, "report-config.yaml")

	if fileutil.FileExists(reportingConfig) {
		return nil
	}
	values := stringslice.StringSlice{Value: []string{}}

	options := &Options{
		AllowList:             &Filter{Tags: values},
		DenyList:              &Filter{Tags: values},
		GitHub:                &github.Options{},
		GitLab:                &gitlab.Options{},
		Jira:                  &jira.Options{},
		MarkdownExporter:      &markdown.Options{},
		SarifExporter:         &sarif.Options{},
		ElasticsearchExporter: &es.Options{},
	}
	reportingFile, err := os.Create(reportingConfig)
	if err != nil {
		return errors.Wrap(err, "could not create config file")
	}
	defer reportingFile.Close()

	err = yaml.NewEncoder(reportingFile).Encode(options)
	return err
}

// RegisterTracker registers a custom tracker to the reporter
func (c *Client) RegisterTracker(tracker Tracker) {
	c.trackers = append(c.trackers, tracker)
}

// RegisterExporter registers a custom exporter to the reporter
func (c *Client) RegisterExporter(exporter Exporter) {
	c.exporters = append(c.exporters, exporter)
}

// Close closes the issue tracker reporting client
func (c *Client) Close() {
	c.dedupe.Close()
	for _, exporter := range c.exporters {
		exporter.Close()
	}
}

// CreateIssue creates an issue in the tracker
func (c *Client) CreateIssue(event *output.ResultEvent) error {
	if c.options.AllowList != nil && !c.options.AllowList.GetMatch(event) {
		return nil
	}
	if c.options.DenyList != nil && c.options.DenyList.GetMatch(event) {
		return nil
	}

	unique, err := c.dedupe.Index(event)
	if unique {
		for _, tracker := range c.trackers {
			if trackerErr := tracker.CreateIssue(event); trackerErr != nil {
				err = multierr.Append(err, trackerErr)
			}
		}
		for _, exporter := range c.exporters {
			if exportErr := exporter.Export(event); exportErr != nil {
				err = multierr.Append(err, exportErr)
			}
		}
	}
	return err
}

func stringSliceContains(slice []string, item string) bool {
	for _, i := range slice {
		if strings.EqualFold(i, item) {
			return true
		}
	}
	return false
}
