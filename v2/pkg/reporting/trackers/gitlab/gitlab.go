package gitlab

import (
	"fmt"

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
	// BaseURL is the optional self-hosted gitlab application url
	BaseURL string `yaml:"base-url"`
	// Username is the mandatory username of the gitlab user
	Username string `yaml:"username"`
	// Token is the mandatory token for gitlab account.
	Token string `yaml:"token"`
	// ProjectName is the mandatory name of the repository.
	ProjectName string `yaml:"project-name"`
	// IssueLabel is the mandatory label of the created issue type
	IssueLabel string `yaml:"issue-label"`
}

// New creates a new issue tracker integration client based on options.
func New(options *Options) (*Integration, error) {
	err := validateOptions(options)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse config")
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
	if options.Username == "" {
		return errors.New("Username name is mandatory")
	}
	if options.Token == "" {
		return errors.New("Token name is mandatory")
	}
	if options.ProjectName == "" {
		return errors.New("ProjectName name is mandatory")
	}
	if options.IssueLabel == "" {
		return errors.New("IssueLabel name is mandatory")
	}
	return nil
}

// CreateIssue creates an issue in the tracker
func (i *Integration) CreateIssue(event *output.ResultEvent) error {
	summary := format.Summary(event)
	description := format.MarkdownDescription(event)
	severityLabel := fmt.Sprintf("Severity: %s", event.Info.SeverityHolder.Severity.String())

	_, _, err := i.client.Issues.CreateIssue(i.options.ProjectName, &gitlab.CreateIssueOptions{
		Title:       &summary,
		Description: &description,
		Labels:      gitlab.Labels{i.options.IssueLabel, severityLabel},
		AssigneeIDs: []int{i.userID},
	})

	return err
}
