package linear

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/shurcooL/graphql"

	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/markdown/util"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/format"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/filters"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/linear/jsonutil"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Integration is a client for linear issue tracker integration
type Integration struct {
	url        string
	httpclient *http.Client
	options    *Options
}

// Options contains the configuration options for linear issue tracker client
type Options struct {
	// APIKey is the API key for linear account.
	APIKey string `yaml:"api-key" validate:"required"`

	// AllowList contains a list of allowed events for this tracker
	AllowList *filters.Filter `yaml:"allow-list"`
	// DenyList contains a list of denied events for this tracker
	DenyList *filters.Filter `yaml:"deny-list"`

	// TeamID is the team id for the project
	TeamID string `yaml:"team-id"`
	// ProjectID is the project id for the project
	ProjectID string `yaml:"project-id"`
	// DuplicateIssueCheck is a bool to enable duplicate tracking issue check and update the newest
	DuplicateIssueCheck bool `yaml:"duplicate-issue-check" default:"false"`

	// OpenStateID is the id of the open state for the project
	OpenStateID string `yaml:"open-state-id"`

	HttpClient *retryablehttp.Client `yaml:"-"`
	OmitRaw    bool                  `yaml:"-"`
}

// New creates a new issue tracker integration client based on options.
func New(options *Options) (*Integration, error) {
	httpClient := &http.Client{
		Transport: &addHeaderTransport{
			T:   http.DefaultTransport,
			Key: options.APIKey,
		},
	}
	if options.HttpClient != nil {
		httpClient.Transport = options.HttpClient.HTTPClient.Transport
	}

	integration := &Integration{
		url:        "https://api.linear.app/graphql",
		options:    options,
		httpclient: httpClient,
	}

	return integration, nil
}

// CreateIssue creates an issue in the tracker
func (i *Integration) CreateIssue(event *output.ResultEvent) (*filters.CreateIssueResponse, error) {
	summary := format.Summary(event)
	description := format.CreateReportDescription(event, util.MarkdownFormatter{}, i.options.OmitRaw)
	_ = description

	ctx := context.Background()

	var err error
	var existingIssue *linearIssue
	if i.options.DuplicateIssueCheck {
		existingIssue, err = i.findIssueByTitle(ctx, summary)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	}

	if existingIssue == nil {
		// Create a new issue
		createdIssue, err := i.createIssueLinear(ctx, summary, description, priorityFromSeverity(event.Info.SeverityHolder.Severity))
		if err != nil {
			return nil, err
		}
		return &filters.CreateIssueResponse{
			IssueID:  types.ToString(createdIssue.ID),
			IssueURL: types.ToString(createdIssue.URL),
		}, nil
	} else {
		if existingIssue.State.Name == "Done" {
			// Update the issue state to open
			var issueUpdateInput struct {
				StateID string `json:"stateId"`
			}
			issueUpdateInput.StateID = i.options.OpenStateID
			variables := map[string]interface{}{
				"issueUpdateInput": issueUpdateInput,
				"issueID":          types.ToString(existingIssue.ID),
			}
			var resp struct {
				IssueUpdate struct {
					LastSyncID int `json:"lastSyncId"`
				}
			}
			err := i.doGraphqlRequest(ctx, existingIssueUpdateStateMutation, &resp, variables, "IssueUpdate")
			if err != nil {
				return nil, fmt.Errorf("error reopening issue %s: %s", existingIssue.ID, err)
			}
		}

		commentInput := map[string]interface{}{
			"issueId": types.ToString(existingIssue.ID),
			"body":    description,
		}
		variables := map[string]interface{}{
			"commentCreateInput": commentInput,
		}
		var resp struct {
			CommentCreate struct {
				LastSyncID int `json:"lastSyncId"`
			}
		}
		err := i.doGraphqlRequest(ctx, commentCreateExistingTicketMutation, &resp, variables, "CommentCreate")
		if err != nil {
			return nil, fmt.Errorf("error commenting on issue %s: %s", existingIssue.ID, err)
		}
		return &filters.CreateIssueResponse{
			IssueID:  types.ToString(existingIssue.ID),
			IssueURL: types.ToString(existingIssue.URL),
		}, nil
	}
}

func priorityFromSeverity(sev severity.Severity) float64 {
	switch sev {
	case severity.Critical:
		return linearPriorityCritical
	case severity.High:
		return linearPriorityHigh
	case severity.Medium:
		return linearPriorityMedium
	case severity.Low:
		return linearPriorityLow
	default:
		return linearPriorityNone
	}
}

type createIssueMutation struct {
	IssueCreate struct {
		Issue struct {
			ID         graphql.ID
			Title      graphql.String
			Identifier graphql.String
			State      struct {
				Name graphql.String
			}
			URL graphql.String
		}
	}
}

const (
	createIssueGraphQLMutation = `mutation CreateIssue($input: IssueCreateInput!) {
    issueCreate(input: $input) {
        issue {
            id
            title
            identifier
            state {
                name
            }
            url
        }
    }
}`

	searchExistingTicketQuery = `query ($teamID: ID, $projectID: ID, $title: String!) {
  issues(filter: { 
  	title: { eq: $title }, 
	team: { id: { eq: $teamID } } 
	project: { id: { eq: $projectID } } 
  }) {
    nodes {
      id
      title
      identifier
      state {
        name
      }
      url
    }
  }
}
`

	existingIssueUpdateStateMutation = `mutation IssueUpdate($issueUpdateInput: IssueUpdateInput!, $issueID: String!) {
  issueUpdate(input: $issueUpdateInput, id: $issueID) {
	lastSyncId
  }
}
`

	commentCreateExistingTicketMutation = `mutation CommentCreate($commentCreateInput: CommentCreateInput!) {
  commentCreate(input: $commentCreateInput) {
    lastSyncId
  }
}
`
)

func (i *Integration) createIssueLinear(ctx context.Context, title, description string, priority float64) (*linearIssue, error) {
	var mutation createIssueMutation
	input := map[string]interface{}{
		"title":       title,
		"description": description,
		"priority":    priority,
	}
	if i.options.TeamID != "" {
		input["teamId"] = graphql.ID(i.options.TeamID)
	}
	if i.options.ProjectID != "" {
		input["projectId"] = i.options.ProjectID
	}

	variables := map[string]interface{}{
		"input": input,
	}

	err := i.doGraphqlRequest(ctx, createIssueGraphQLMutation, &mutation, variables, "CreateIssue")
	if err != nil {
		return nil, err
	}

	return &linearIssue{
		ID:         mutation.IssueCreate.Issue.ID,
		Title:      mutation.IssueCreate.Issue.Title,
		Identifier: mutation.IssueCreate.Issue.Identifier,
		State: struct {
			Name graphql.String
		}{
			Name: mutation.IssueCreate.Issue.State.Name,
		},
		URL: mutation.IssueCreate.Issue.URL,
	}, nil
}

func (i *Integration) findIssueByTitle(ctx context.Context, title string) (*linearIssue, error) {
	var query findExistingIssuesSearch
	variables := map[string]interface{}{
		"title": graphql.String(title),
	}
	if i.options.TeamID != "" {
		variables["teamId"] = graphql.ID(i.options.TeamID)
	}
	if i.options.ProjectID != "" {
		variables["projectID"] = graphql.ID(i.options.ProjectID)
	}

	err := i.doGraphqlRequest(ctx, searchExistingTicketQuery, &query, variables, "")
	if err != nil {
		return nil, err
	}

	if len(query.Issues.Nodes) > 0 {
		return &query.Issues.Nodes[0], nil
	}
	return nil, io.EOF
}

func (i *Integration) Name() string {
	return "linear"
}

func (i *Integration) CloseIssue(event *output.ResultEvent) error {
	// TODO: Unimplemented for now as not used in many places
	// and overhead of maintaining our own API for this.
	// This is too much code as it is :(
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

type linearIssue struct {
	ID         graphql.ID
	Title      graphql.String
	Identifier graphql.String
	State      struct {
		Name graphql.String
	}
	URL graphql.String
}

type findExistingIssuesSearch struct {
	Issues struct {
		Nodes []linearIssue
	}
}

// Custom transport to add the API key to the header
type addHeaderTransport struct {
	T   http.RoundTripper
	Key string
}

func (adt *addHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("Authorization", adt.Key)
	return adt.T.RoundTrip(req)
}

const (
	linearPriorityNone     = float64(0)
	linearPriorityCritical = float64(1)
	linearPriorityHigh     = float64(2)
	linearPriorityMedium   = float64(3)
	linearPriorityLow      = float64(4)
)

// errors represents the "errors" array in a response from a GraphQL server.
// If returned via error interface, the slice is expected to contain at least 1 element.
//
// Specification: https://spec.graphql.org/October2021/#sec-Errors.
type errorsGraphql []struct {
	Message   string
	Locations []struct {
		Line   int
		Column int
	}
}

// Error implements error interface.
func (e errorsGraphql) Error() string {
	return e[0].Message
}

// do executes a single GraphQL operation.
func (i *Integration) doGraphqlRequest(ctx context.Context, query string, v any, variables map[string]any, operationName string) error {
	in := struct {
		Query         string         `json:"query"`
		Variables     map[string]any `json:"variables,omitempty"`
		OperationName string         `json:"operationName,omitempty"`
	}{
		Query:         query,
		Variables:     variables,
		OperationName: operationName,
	}

	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.url, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := i.httpclient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("non-200 OK status code: %v body: %q", resp.Status, body)
	}
	var out struct {
		Data   *json.Message
		Errors errorsGraphql
		//Extensions any // Unused.
	}

	err = json.NewDecoder(resp.Body).Decode(&out)
	if err != nil {
		return err
	}
	if out.Data != nil {
		err := jsonutil.UnmarshalGraphQL(*out.Data, v)
		if err != nil {
			return err
		}
	}
	if len(out.Errors) > 0 {
		return out.Errors
	}
	return nil
}
