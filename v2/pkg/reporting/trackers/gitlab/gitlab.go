package gitlab

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/format"
	"github.com/xanzy/go-gitlab"
)

// Integration is a client for an issue tracker integration
type Integration struct {
	client  *gitlab.Client
	userID  int
	options *Options
}

// Options contains the configuration options for gitlab issue tracker client
type Options struct {
	// BaseURL (optional) is the self-hosted gitlab application url
	BaseURL string `yaml:"base-url"`
	// Username is the username of the gitlab user
	Username string `yaml:"username"`
	// Token is the token for gitlab account.
	Token string `yaml:"token"`
	// ProjectName is the name of the repository.
	ProjectName string `yaml:"project-name"`
	// IssueLabel is the label of the created issue type
	IssueLabel string `yaml:"issue-label"`
	// SeverityAsLabel (optional) sends the severity as the label of the created
	// issue.
	SeverityAsLabel bool `yaml:"severity-as-label"`
}

// New creates a new issue tracker integration client based on options.
func New(options *Options) (*Integration, error) {
	err := validateOptions(options)
	if err != nil {
		return nil, err
	}
	gitlabOpts := []gitlab.ClientOptionFunc{}
	if options.BaseURL != "" {
		gitlabOpts = append(gitlabOpts, gitlab.WithBaseURL(options.BaseURL))
	}
	git, err := gitlab.NewClient(options.Token, gitlabOpts...)
	if err != nil {
		return nil, err
	}
	user, _, err := git.Users.CurrentUser()
	if err != nil {
		return nil, err
	}
	return &Integration{client: git, userID: user.ID, options: options}, nil
}

func validateOptions(options *Options) error {
	errs := []string{}
	if options.Username == "" {
		errs = append(errs, "Username")
	}
	if options.Token == "" {
		errs = append(errs, "Token")
	}
	if options.ProjectName == "" {
		errs = append(errs, "ProjectName")
	}

	if len(errs) > 0 {
		return errors.New("Mandatory reporting configuration fields are missing: " + strings.Join(errs, ","))
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

	_, _, err := i.client.Issues.CreateIssue(i.options.ProjectName, &gitlab.CreateIssueOptions{
		Title:       &summary,
		Description: &description,
		Labels:      labels,
		AssigneeIDs: []int{i.userID},
	})

	return err
}
