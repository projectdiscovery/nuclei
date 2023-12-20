package gitea

import (
	"fmt"
	"net/url"
	"strings"

	"code.gitea.io/sdk/gitea"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/markdown/util"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/format"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Integration is a client for an issue tracker integration
type Integration struct {
	client  *gitea.Client
	options *Options
}

// Options contains the configuration options for gitlab issue tracker client
type Options struct {
	// BaseURL (optional) is the self-hosted Gitea application url
	BaseURL string `yaml:"base-url" validate:"omitempty,url"`
	// Token is the token for gitea account.
	Token string `yaml:"token" validate:"required"`
	// ProjectOwner is the owner (user or org) of the repository.
	ProjectOwner string `yaml:"project-owner" validate:"required"`
	// ProjectName is the name of the repository.
	ProjectName string `yaml:"project-name" validate:"required"`
	// IssueLabel is the label of the created issue type
	IssueLabel string `yaml:"issue-label"`
	// SeverityAsLabel (optional) sends the severity as the label of the created
	// issue.
	SeverityAsLabel bool `yaml:"severity-as-label"`
	// DuplicateIssueCheck is a bool to enable duplicate tracking issue check and update the newest
	DuplicateIssueCheck bool `yaml:"duplicate-issue-check" default:"false"`

	HttpClient *retryablehttp.Client `yaml:"-"`
}

// New creates a new issue tracker integration client based on options.
func New(options *Options) (*Integration, error) {

	var opts []gitea.ClientOption
	opts = append(opts, gitea.SetToken(options.Token))

	if options.HttpClient != nil {
		opts = append(opts, gitea.SetHTTPClient(options.HttpClient.HTTPClient))
	}

	var remote string
	if options.BaseURL != "" {
		parsed, err := url.Parse(options.BaseURL)
		if err != nil {
			return nil, errors.Wrap(err, "could not parse custom baseurl")
		}
		if !strings.HasSuffix(parsed.Path, "/") {
			parsed.Path += "/"
		}
		remote = parsed.String()
	} else {
		remote = `https://gitea.com/`
	}

	git, err := gitea.NewClient(remote, opts...)
	if err != nil {
		return nil, err
	}

	return &Integration{client: git, options: options}, nil
}

// CreateIssue creates an issue in the tracker
func (i *Integration) CreateIssue(event *output.ResultEvent) error {
	summary := format.Summary(event)
	description := format.CreateReportDescription(event, util.MarkdownFormatter{})

	labels := []string{}
	severityLabel := fmt.Sprintf("Severity: %s", event.Info.SeverityHolder.Severity.String())
	if i.options.SeverityAsLabel && severityLabel != "" {
		labels = append(labels, severityLabel)
	}
	if label := i.options.IssueLabel; label != "" {
		labels = append(labels, label)
	}
	customLabels, err := i.getLabelIDsByNames(labels)
	if err != nil {
		return err
	}

	var issue *gitea.Issue
	if i.options.DuplicateIssueCheck {
		issue, err = i.findIssueByTitle(summary)
		if err != nil {
			return err
		}
	}

	if issue == nil {
		_, _, err = i.client.CreateIssue(i.options.ProjectOwner, i.options.ProjectName, gitea.CreateIssueOption{
			Title:  summary,
			Body:   description,
			Labels: customLabels,
		})

		return err
	}

	_, _, err = i.client.CreateIssueComment(i.options.ProjectOwner, i.options.ProjectName, issue.ID, gitea.CreateIssueCommentOption{
		Body: description,
	})

	return err
}

func (i *Integration) findIssueByTitle(title string) (*gitea.Issue, error) {

	issueList, _, err := i.client.ListRepoIssues(i.options.ProjectOwner, i.options.ProjectName, gitea.ListIssueOption{
		State: "all",
	})
	if err != nil {
		return nil, err
	}

	for _, issue := range issueList {
		if issue.Title == title {
			return issue, nil
		}
	}

	return nil, nil
}

func (i *Integration) getLabelIDsByNames(labels []string) ([]int64, error) {

	var ids []int64

	existingLabels, _, err := i.client.ListRepoLabels(i.options.ProjectOwner, i.options.ProjectName, gitea.ListLabelsOptions{
		ListOptions: gitea.ListOptions{Page: -1},
	})
	if err != nil {
		return nil, err
	}

	getLabel := func(name string) int64 {
		for _, existingLabel := range existingLabels {
			if existingLabel.Name == name {
				return existingLabel.ID
			}
		}
		return -1
	}

	for _, label := range labels {
		labelID := getLabel(label)
		if labelID == -1 {
			newLabel, _, err := i.client.CreateLabel(i.options.ProjectOwner, i.options.ProjectName, gitea.CreateLabelOption{
				Name:        label,
				Color:       `#00aabb`,
				Description: label,
			})
			if err != nil {
				return nil, err
			}

			ids = append(ids, newLabel.ID)
		} else {
			ids = append(ids, labelID)
		}
	}

	return ids, nil
}
