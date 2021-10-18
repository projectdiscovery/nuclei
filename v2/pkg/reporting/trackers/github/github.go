package github

import (
	"context"
	"fmt"
	"net/url"

	"golang.org/x/oauth2"

	"github.com/google/go-github/github"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/format"
)

// Integration is a client for an issue tracker integration
type Integration struct {
	client  *github.Client
	options *Options
}

// Options contains the configuration options for github issue tracker client
type Options struct {
	// BaseURL (optional) is the self-hosted github application url
	BaseURL string `yaml:"base-url"`
	// Username (mandatory) is the username of the github user
	Username string `yaml:"username"`
	// Owner (manadatory) is the owner name of the repository for issues.
	Owner string `yaml:"owner"`
	// Token (mandatory) is the token for github account.
	Token string `yaml:"token"`
	// ProjectName (mandatory) is the name of the repository.
	ProjectName string `yaml:"project-name"`
	// IssueLabel (optional) is the label of the created issue type
	IssueLabel string `yaml:"issue-label"`
	// SeverityAsLabel (optional) sends the severity as the label of the created
	// issue.
	SeverityAsLabel bool `yaml:"severity-as-label"`
}

// New creates a new issue tracker integration client based on options.
func New(options *Options) (*Integration, error) {
	err := validateOptions(options)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse config")
	}
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: options.Token},
	)
	tc := oauth2.NewClient(ctx, ts)

	client := github.NewClient(tc)
	if options.BaseURL != "" {
		parsed, err := url.Parse(options.BaseURL)
		if err != nil {
			return nil, errors.Wrap(err, "could not parse custom baseurl")
		}
		client.BaseURL = parsed
	}
	return &Integration{client: client, options: options}, nil
}

func validateOptions(options *Options) error {
	if options.Username == "" {
		return errors.New("Username name is mandatory")
	}
	if options.Owner == "" {
		return errors.New("Owner name is mandatory")
	}
	if options.Token == "" {
		return errors.New("Token name is mandatory")
	}
	if options.ProjectName == "" {
		return errors.New("ProjectName name is mandatory")
	}
	return nil
}

// CreateIssue creates an issue in the tracker
func (i *Integration) CreateIssue(event *output.ResultEvent) error {
	summary := format.Summary(event)
	description := format.MarkdownDescription(event)
	labels := []string{}
	severityLabel := fmt.Sprintf("Severity: %s", event.Info.SeverityHolder.Severity.String())
	if i.options.SeverityAsLabel && severityLabel != "" {
		labels = append(labels, severityLabel)
	}
	if label := i.options.IssueLabel; label != "" {
		labels = append(labels, label)
	}

	req := &github.IssueRequest{
		Title:     &summary,
		Body:      &description,
		Labels:    &labels,
		Assignees: &[]string{i.options.Username},
	}
	_, _, err := i.client.Issues.Create(context.Background(), i.options.Owner, i.options.ProjectName, req)
	return err
}
