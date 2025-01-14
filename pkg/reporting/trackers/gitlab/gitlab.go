package gitlab

import (
	"fmt"
	"strconv"

	"github.com/xanzy/go-gitlab"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/markdown/util"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/format"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/filters"
	"github.com/projectdiscovery/retryablehttp-go"
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
	BaseURL string `yaml:"base-url" validate:"omitempty,url"`
	// Username is the username of the gitlab user
	Username string `yaml:"username" validate:"required"`
	// Token is the token for gitlab account.
	Token string `yaml:"token" validate:"required"`
	// ProjectName is the name of the repository.
	ProjectName string `yaml:"project-name" validate:"required"`
	// IssueLabel is the label of the created issue type
	IssueLabel string `yaml:"issue-label"`
	// SeverityAsLabel (optional) sends the severity as the label of the created
	// issue.
	SeverityAsLabel bool `yaml:"severity-as-label"`
	// AllowList contains a list of allowed events for this tracker
	AllowList *filters.Filter `yaml:"allow-list"`
	// DenyList contains a list of denied events for this tracker
	DenyList *filters.Filter `yaml:"deny-list"`
	// DuplicateIssueCheck is a bool to enable duplicate tracking issue check and update the newest
	DuplicateIssueCheck bool `yaml:"duplicate-issue-check" default:"false"`

	HttpClient *retryablehttp.Client `yaml:"-"`
	OmitRaw    bool                  `yaml:"-"`
}

// New creates a new issue tracker integration client based on options.
func New(options *Options) (*Integration, error) {
	gitlabOpts := []gitlab.ClientOptionFunc{}
	if options.BaseURL != "" {
		gitlabOpts = append(gitlabOpts, gitlab.WithBaseURL(options.BaseURL))
	}
	if options.HttpClient != nil {
		gitlabOpts = append(gitlabOpts, gitlab.WithHTTPClient(options.HttpClient.HTTPClient))
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

// CreateIssue creates an issue in the tracker
func (i *Integration) CreateIssue(event *output.ResultEvent) (*filters.CreateIssueResponse, error) {
	summary := format.Summary(event)
	description := format.CreateReportDescription(event, util.MarkdownFormatter{}, i.options.OmitRaw)
	labels := []string{}
	severityLabel := fmt.Sprintf("Severity: %s", event.Info.SeverityHolder.Severity.String())
	if i.options.SeverityAsLabel && severityLabel != "" {
		labels = append(labels, severityLabel)
	}
	if label := i.options.IssueLabel; label != "" {
		labels = append(labels, label)
	}
	customLabels := gitlab.LabelOptions(labels)
	assigneeIDs := []int{i.userID}
	if i.options.DuplicateIssueCheck {
		searchIn := "title"
		searchState := "all"
		issues, _, err := i.client.Issues.ListProjectIssues(i.options.ProjectName, &gitlab.ListProjectIssuesOptions{
			In:     &searchIn,
			State:  &searchState,
			Search: &summary,
		})
		if err != nil {
			return nil, err
		}
		if len(issues) > 0 {
			issue := issues[0]
			_, _, err := i.client.Notes.CreateIssueNote(i.options.ProjectName, issue.IID, &gitlab.CreateIssueNoteOptions{
				Body: &description,
			})
			if err != nil {
				return nil, err
			}
			if issue.State == "closed" {
				reopen := "reopen"
				_, _, err := i.client.Issues.UpdateIssue(i.options.ProjectName, issue.IID, &gitlab.UpdateIssueOptions{
					StateEvent: &reopen,
				})
				if err != nil {
					return nil, err
				}
			}
			return &filters.CreateIssueResponse{
				IssueID:  strconv.FormatInt(int64(issue.ID), 10),
				IssueURL: issue.WebURL,
			}, nil
		}
	}
	createdIssue, _, err := i.client.Issues.CreateIssue(i.options.ProjectName, &gitlab.CreateIssueOptions{
		Title:       &summary,
		Description: &description,
		Labels:      &customLabels,
		AssigneeIDs: &assigneeIDs,
	})
	if err != nil {
		return nil, err
	}
	return &filters.CreateIssueResponse{
		IssueID:  strconv.FormatInt(int64(createdIssue.ID), 10),
		IssueURL: createdIssue.WebURL,
	}, nil
}

func (i *Integration) Name() string {
	return "gitlab"
}

func (i *Integration) CloseIssue(event *output.ResultEvent) error {
	searchIn := "title"
	searchState := "all"

	summary := format.Summary(event)
	issues, _, err := i.client.Issues.ListProjectIssues(i.options.ProjectName, &gitlab.ListProjectIssuesOptions{
		In:     &searchIn,
		State:  &searchState,
		Search: &summary,
	})
	if err != nil {
		return err
	}
	if len(issues) <= 0 {
		return nil
	}

	issue := issues[0]
	state := "close"
	_, _, err = i.client.Issues.UpdateIssue(i.options.ProjectName, issue.IID, &gitlab.UpdateIssueOptions{
		StateEvent: &state,
	})
	if err != nil {
		return err
	}
	return nil
}

// ShouldFilter determines if an issue should be logged to this tracker
func (i *Integration) ShouldFilter(event *output.ResultEvent) bool {
	if i.options.AllowList != nil && !i.options.AllowList.GetMatch(event) {
		return false
	}

	if i.options.DenyList != nil && i.options.DenyList.GetMatch(event) {
		return false
	}

	return true
}
