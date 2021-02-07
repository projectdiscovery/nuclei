package issues

import (
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/issues/dedupe"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/issues/github"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/issues/gitlab"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/issues/jira"
	"gopkg.in/yaml.v2"
)

// Options is a configuration file for nuclei reporting module
type Options struct {
	// AllowList contains a list of allowed events for reporting module
	AllowList *Filter `yaml:"allow-list"`
	// DenyList contains a list of denied events for reporting module
	DenyList *Filter `yaml:"deny-list"`
	// Github contains configuration options for Github Issue Tracker
	Github *github.Options `yaml:"github"`
	// Gitlab contains configuration options for Gitlab Issue Tracker
	Gitlab *gitlab.Options `yaml:"gitlab"`
	// Jira contains configuration options for Jira Issue Tracker
	Jira *jira.Options `yaml:"jira"`
}

// Filter filters the received event and decides whether to perform
// reporting for it or not.
type Filter struct {
	Severity string `yaml:"severity"`
	severity []string
	Tags     string `yaml:"tags"`
	tags     []string
}

// Compile compiles the filter creating match structures.
func (f *Filter) Compile() {
	parts := strings.Split(f.Severity, ",")
	for _, part := range parts {
		f.severity = append(f.severity, strings.TrimSpace(part))
	}
	parts = strings.Split(f.Tags, ",")
	for _, part := range parts {
		f.tags = append(f.tags, strings.TrimSpace(part))
	}
}

// GetMatch returns true if a filter matches result event
func (f *Filter) GetMatch(event *output.ResultEvent) bool {
	severity := event.Info["severity"]
	if len(f.severity) > 0 {
		if stringSliceContains(f.severity, severity) {
			return true
		}
		return false
	}

	tags := event.Info["tags"]
	tagParts := strings.Split(tags, ",")
	for i, tag := range tagParts {
		tagParts[i] = strings.TrimSpace(tag)
	}
	for _, tag := range f.tags {
		if stringSliceContains(tagParts, tag) {
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

// Client is a client for nuclei issue tracking module
type Client struct {
	tracker Tracker
	options *Options
	dedupe  *dedupe.Storage
}

// New creates a new nuclei issue tracker reporting client
func New(config, db string) (*Client, error) {
	file, err := os.Open(config)
	if err != nil {
		return nil, errors.Wrap(err, "could not open reporting config file")
	}
	defer file.Close()

	options := &Options{}
	if err := yaml.NewDecoder(file).Decode(options); err != nil {
		return nil, err
	}
	if options.AllowList != nil {
		options.AllowList.Compile()
	}
	if options.DenyList != nil {
		options.DenyList.Compile()
	}

	var tracker Tracker
	if options.Github != nil {
		tracker, err = github.New(options.Github)
	}
	if options.Gitlab != nil {
		tracker, err = gitlab.New(options.Gitlab)
	}
	if options.Jira != nil {
		tracker, err = jira.New(options.Jira)
	}
	if err != nil {
		return nil, errors.Wrap(err, "could not create reporting client")
	}
	if tracker == nil {
		return nil, errors.New("no issue tracker configuration found")
	}
	storage, err := dedupe.New(db)
	if err != nil {
		return nil, err
	}
	return &Client{tracker: tracker, dedupe: storage, options: options}, nil
}

// Close closes the issue tracker reporting client
func (c *Client) Close() {
	c.dedupe.Close()
}

// CreateIssue creates an issue in the tracker
func (c *Client) CreateIssue(event *output.ResultEvent) error {
	if c.options.AllowList != nil && !c.options.AllowList.GetMatch(event) {
		return nil
	}
	if c.options.DenyList != nil && c.options.DenyList.GetMatch(event) {
		return nil
	}

	found, err := c.dedupe.Index(event)
	if err != nil {
		c.tracker.CreateIssue(event)
		return err
	}
	if found {
		return c.tracker.CreateIssue(event)
	}
	return nil
}

func stringSliceContains(slice []string, item string) bool {
	for _, i := range slice {
		if strings.EqualFold(i, item) {
			return true
		}
	}
	return false
}
