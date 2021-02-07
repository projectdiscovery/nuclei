package issues

import (
	"os"

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
	// Github contains configuration options for Github Issue Tracker
	Github *github.Options `yaml:"github"`
	// Gitlab contains configuration options for Gitlab Issue Tracker
	Gitlab *gitlab.Options `yaml:"gitlab"`
	// Jira contains configuration options for Jira Issue Tracker
	Jira *jira.Options `yaml:"jira"`
}

// Tracker is an interface implemented by an issue tracker
type Tracker interface {
	// CreateIssue creates an issue in the tracker
	CreateIssue(event *output.ResultEvent) error
}

// Client is a client for nuclei issue tracking module
type Client struct {
	tracker Tracker
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
	return &Client{tracker: tracker, dedupe: storage}, nil
}

// Close closes the issue tracker reporting client
func (c *Client) Close() {
	c.dedupe.Close()
}

// CreateIssue creates an issue in the tracker
func (c *Client) CreateIssue(event *output.ResultEvent) error {
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
