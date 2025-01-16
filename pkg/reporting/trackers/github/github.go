package github

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/go-github/github"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/markdown/util"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/format"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/filters"
	"github.com/projectdiscovery/retryablehttp-go"
	"golang.org/x/oauth2"
)

// Integration is a client for an issue tracker integration
type Integration struct {
	client  *github.Client
	options *Options
}

// Options contains the configuration options for GitHub issue tracker client
type Options struct {
	// BaseURL (optional) is the self-hosted GitHub application url
	BaseURL string `yaml:"base-url" validate:"omitempty,url"`
	// Username is the username of the GitHub user
	Username string `yaml:"username" validate:"required"`
	// Owner is the owner name of the repository for issues.
	Owner string `yaml:"owner" validate:"required"`
	// Token is the token for GitHub account.
	Token string `yaml:"token" validate:"required"`
	// ProjectName is the name of the repository.
	ProjectName string `yaml:"project-name" validate:"required"`
	// IssueLabel (optional) is the label of the created issue type
	IssueLabel string `yaml:"issue-label"`
	// SeverityAsLabel (optional) sends the severity as the label of the created
	// issue.
	SeverityAsLabel bool `yaml:"severity-as-label"`
	// AllowList contains a list of allowed events for this tracker
	AllowList *filters.Filter `yaml:"allow-list"`
	// DenyList contains a list of denied events for this tracker
	DenyList *filters.Filter `yaml:"deny-list"`
	// DuplicateIssueCheck (optional) comments under existing finding issue
	// instead of creating duplicates for subsequent runs.
	DuplicateIssueCheck bool `yaml:"duplicate-issue-check"`

	HttpClient *retryablehttp.Client `yaml:"-"`
	OmitRaw    bool                  `yaml:"-"`
}

// New creates a new issue tracker integration client based on options.
func New(options *Options) (*Integration, error) {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: options.Token},
	)
	tc := oauth2.NewClient(ctx, ts)

	if options.HttpClient != nil && options.HttpClient.HTTPClient != nil {
		if tcTransport, ok := tc.Transport.(*http.Transport); ok {
			tcTransport.Proxy = options.HttpClient.HTTPClient.Transport.(*http.Transport).Proxy
		}
	}

	client := github.NewClient(tc)
	if options.BaseURL != "" {
		parsed, err := url.Parse(options.BaseURL)
		if err != nil {
			return nil, errors.Wrap(err, "could not parse custom baseurl")
		}
		if !strings.HasSuffix(parsed.Path, "/") {
			parsed.Path += "/"
		}
		client.BaseURL = parsed
	}
	return &Integration{client: client, options: options}, nil
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

	ctx := context.Background()

	var err error
	var existingIssue *github.Issue
	if i.options.DuplicateIssueCheck {
		existingIssue, err = i.findIssueByTitle(ctx, summary)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	}

	if existingIssue == nil {
		req := &github.IssueRequest{
			Title:     &summary,
			Body:      &description,
			Labels:    &labels,
			Assignees: &[]string{i.options.Username},
		}
		createdIssue, _, err := i.client.Issues.Create(ctx, i.options.Owner, i.options.ProjectName, req)
		if err != nil {
			return nil, err
		}
		return &filters.CreateIssueResponse{
			IssueID:  strconv.FormatInt(createdIssue.GetID(), 10),
			IssueURL: createdIssue.GetHTMLURL(),
		}, nil
	} else {
		if existingIssue.GetState() == "closed" {
			stateOpen := "open"
			if _, _, err := i.client.Issues.Edit(ctx, i.options.Owner, i.options.ProjectName, *existingIssue.Number, &github.IssueRequest{
				State: &stateOpen,
			}); err != nil {
				return nil, fmt.Errorf("error reopening issue %d: %s", *existingIssue.Number, err)
			}
		}

		req := &github.IssueComment{
			Body: &description,
		}
		_, _, err = i.client.Issues.CreateComment(ctx, i.options.Owner, i.options.ProjectName, *existingIssue.Number, req)
		if err != nil {
			return nil, err
		}
		return &filters.CreateIssueResponse{
			IssueID:  strconv.FormatInt(existingIssue.GetID(), 10),
			IssueURL: existingIssue.GetHTMLURL(),
		}, nil
	}
}

func (i *Integration) CloseIssue(event *output.ResultEvent) error {
	ctx := context.Background()
	summary := format.Summary(event)

	existingIssue, err := i.findIssueByTitle(ctx, summary)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if existingIssue == nil {
		return nil
	}

	stateClosed := "closed"
	if _, _, err := i.client.Issues.Edit(ctx, i.options.Owner, i.options.ProjectName, *existingIssue.Number, &github.IssueRequest{
		State: &stateClosed,
	}); err != nil {
		return fmt.Errorf("error closing issue %d: %s", *existingIssue.Number, err)
	}
	return nil
}

func (i *Integration) Name() string {
	return "github"
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

func (i *Integration) findIssueByTitle(ctx context.Context, title string) (*github.Issue, error) {
	req := &github.SearchOptions{
		Sort:      "updated",
		Order:     "desc",
		TextMatch: false,
		ListOptions: github.ListOptions{
			Page:    1,
			PerPage: 100,
		},
	}

	query := fmt.Sprintf(`is:issue repo:%s/%s "%s"`, i.options.Owner, i.options.ProjectName, title)

	for {
		issues, resp, err := i.client.Search.Issues(ctx, query, req)
		if err != nil {
			return nil, fmt.Errorf("error listing issues for %s, %s: %w", i.options.Owner, i.options.ProjectName, err)
		}

		for _, issue := range issues.Issues {
			if issue.Title != nil && *issue.Title == title {
				return &issue, nil
			}
		}

		if resp.NextPage <= req.Page || len(issues.Issues) == 0 {
			return nil, io.EOF
		}

		req.ListOptions = github.ListOptions{
			Page:    resp.NextPage,
			PerPage: 100,
		}
	}
}
