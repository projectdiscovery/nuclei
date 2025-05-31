package jira

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/andygrunwald/go-jira"
	"github.com/pkg/errors"
	"github.com/trivago/tgo/tcontainer"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/markdown/util"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/format"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/filters"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/utils/ptr"
)

type Formatter struct {
	util.MarkdownFormatter
}

func (jiraFormatter *Formatter) MakeBold(text string) string {
	return "*" + text + "*"
}

func (jiraFormatter *Formatter) CreateCodeBlock(title string, content string, _ string) string {
	escapedContent := strings.ReplaceAll(content, "{code}", "")
	return fmt.Sprintf("\n%s\n{code}\n%s\n{code}\n", jiraFormatter.MakeBold(title), escapedContent)
}

func (jiraFormatter *Formatter) CreateTable(headers []string, rows [][]string) (string, error) {
	if len(headers) == 0 {
		return "", fmt.Errorf("no headers provided")
	}

	var builder strings.Builder

	// Create header row with leading and trailing pipes
	builder.WriteString("| ")
	builder.WriteString(strings.Join(headers, " | "))
	builder.WriteString(" |")
	builder.WriteString("\n")

	// Create separator row with leading and trailing pipes
	separators := make([]string, len(headers))
	for i := range separators {
		separators[i] = "-----------"
	}
	builder.WriteString("|")
	builder.WriteString(strings.Join(separators, "|"))
	builder.WriteString("|")
	builder.WriteString("\n")

	// Create data rows with leading and trailing pipes
	for _, row := range rows {
		builder.WriteString("| ")
		if len(row) < len(headers) {
			extendedRow := make([]string, len(headers))
			copy(extendedRow, row)
			builder.WriteString(strings.Join(extendedRow, " | "))
		} else if len(row) > len(headers) {
			builder.WriteString(strings.Join(row[:len(headers)], " | "))
		} else {
			builder.WriteString(strings.Join(row, " | "))
		}
		builder.WriteString(" |")
		builder.WriteString("\n")
	}

	return builder.String(), nil
}

func (jiraFormatter *Formatter) CreateHorizontalLine() string {
	return "----\n"
}

func (jiraFormatter *Formatter) FormatLineBreaks(text string) string {
	return strings.ReplaceAll(text, "\n", "\\\\")
}

func (jiraFormatter *Formatter) CreateLink(title string, url string) string {
	return fmt.Sprintf("[%s](%s)", title, url)
}

// Integration is a client for an issue tracker integration
type Integration struct {
	Formatter
	jira    *jira.Client
	options *Options

	once         *sync.Once
	transitionID string
}

// Options contains the configuration options for jira client
type Options struct {
	// Cloud value (optional) is set to true when Jira cloud is used
	Cloud bool `yaml:"cloud" json:"cloud"`
	// UpdateExisting value (optional) if true, the existing opened issue is updated
	UpdateExisting bool `yaml:"update-existing" json:"update_existing"`
	// URL is the URL of the jira server
	URL string `yaml:"url" json:"url" validate:"required"`
	// AccountID is the accountID of the jira user.
	AccountID string `yaml:"account-id" json:"account_id" validate:"required"`
	// Email is the email of the user for jira instance
	Email string `yaml:"email" json:"email"`
	// PersonalAccessToken is the personal access token for jira instance.
	// If this is set, Bearer Auth is used instead of Basic Auth.
	PersonalAccessToken string `yaml:"personal-access-token" json:"personal_access_token"`
	// Token is the token for jira instance.
	Token string `yaml:"token" json:"token"`
	// ProjectName is the name of the project.
	ProjectName string `yaml:"project-name" json:"project_name"`
	// ProjectID is the ID of the project (optional)
	ProjectID string `yaml:"project-id" json:"project_id"`
	// IssueType (optional) is the name of the created issue type
	IssueType string `yaml:"issue-type" json:"issue_type"`
	// IssueTypeID (optional) is the ID of the created issue type
	IssueTypeID string `yaml:"issue-type-id" json:"issue_type_id"`
	// SeverityAsLabel (optional) sends the severity as the label of the created
	// issue.
	SeverityAsLabel bool `yaml:"severity-as-label" json:"severity_as_label"`
	// AllowList contains a list of allowed events for this tracker
	AllowList *filters.Filter `yaml:"allow-list"`
	// DenyList contains a list of denied events for this tracker
	DenyList *filters.Filter `yaml:"deny-list"`
	// Severity (optional) is the severity of the issue.
	Severity   []string              `yaml:"severity" json:"severity"`
	HttpClient *retryablehttp.Client `yaml:"-" json:"-"`
	// for each customfield specified in the configuration options
	// we will create a map of customfield name to the value
	// that will be used to create the issue
	CustomFields map[string]interface{} `yaml:"custom-fields" json:"custom_fields"`
	StatusNot    string                 `yaml:"status-not" json:"status_not"`
	OmitRaw      bool                   `yaml:"-"`
}

// New creates a new issue tracker integration client based on options.
func New(options *Options) (*Integration, error) {
	username := options.Email
	if !options.Cloud {
		username = options.AccountID
	}

	var httpclient *http.Client
	if options.PersonalAccessToken != "" {
		bearerTp := jira.BearerAuthTransport{
			Token: options.PersonalAccessToken,
		}
		if options.HttpClient != nil {
			bearerTp.Transport = options.HttpClient.HTTPClient.Transport
		}
		httpclient = bearerTp.Client()
	} else {
		basicTp := jira.BasicAuthTransport{
			Username: username,
			Password: options.Token,
		}
		if options.HttpClient != nil {
			basicTp.Transport = options.HttpClient.HTTPClient.Transport
		}
		httpclient = basicTp.Client()
	}

	jiraClient, err := jira.NewClient(httpclient, options.URL)
	if err != nil {
		return nil, err
	}
	integration := &Integration{
		jira:    jiraClient,
		options: options,
		once:    &sync.Once{},
	}
	return integration, nil
}

func (i *Integration) Name() string {
	return "jira"
}

// CreateNewIssue creates a new issue in the tracker
func (i *Integration) CreateNewIssue(event *output.ResultEvent) (*filters.CreateIssueResponse, error) {
	summary := format.Summary(event)
	labels := []string{}
	severityLabel := fmt.Sprintf("Severity:%s", event.Info.SeverityHolder.Severity.String())
	if i.options.SeverityAsLabel && severityLabel != "" {
		labels = append(labels, severityLabel)
	}
	if label := i.options.IssueType; label != "" {
		labels = append(labels, label)
	}
	// for each custom value, take the name of the custom field and
	// set the value of the custom field to the value specified in the
	// configuration options
	customFields := tcontainer.NewMarshalMap()
	for name, value := range i.options.CustomFields {
		//customFields[name] = map[string]interface{}{"value": value}
		if valueMap, ok := value.(map[interface{}]interface{}); ok {
			// Iterate over nested map
			for nestedName, nestedValue := range valueMap {
				fmtNestedValue, ok := nestedValue.(string)
				if !ok {
					return nil, fmt.Errorf(`couldn't iterate on nested item "%s": %s`, nestedName, nestedValue)
				}
				if strings.HasPrefix(fmtNestedValue, "$") {
					nestedValue = strings.TrimPrefix(fmtNestedValue, "$")
					switch nestedValue {
					case "CVSSMetrics":
						nestedValue = ptr.Safe(event.Info.Classification).CVSSMetrics
					case "CVEID":
						nestedValue = ptr.Safe(event.Info.Classification).CVEID
					case "CWEID":
						nestedValue = ptr.Safe(event.Info.Classification).CWEID
					case "CVSSScore":
						nestedValue = ptr.Safe(event.Info.Classification).CVSSScore
					case "Host":
						nestedValue = event.Host
					case "Severity":
						nestedValue = event.Info.SeverityHolder
					case "Name":
						nestedValue = event.Info.Name
					}
				}
				switch nestedName {
				case "id":
					customFields[name] = map[string]interface{}{"id": nestedValue}
				case "name":
					customFields[name] = map[string]interface{}{"value": nestedValue}
				case "freeform":
					customFields[name] = nestedValue
				}
			}
		}
	}
	fields := &jira.IssueFields{
		Assignee:    &jira.User{Name: i.options.AccountID},
		Description: format.CreateReportDescription(event, i, i.options.OmitRaw),
		Unknowns:    customFields,
		Labels:      labels,
		Type:        jira.IssueType{Name: i.options.IssueType},
		Project:     jira.Project{Key: i.options.ProjectName},
		Summary:     summary,
	}

	// On-prem version of Jira server does not use AccountID
	if !i.options.Cloud {
		fields = &jira.IssueFields{
			Assignee:    &jira.User{Name: i.options.AccountID},
			Description: format.CreateReportDescription(event, i, i.options.OmitRaw),
			Type:        jira.IssueType{Name: i.options.IssueType},
			Project:     jira.Project{Key: i.options.ProjectName},
			Summary:     summary,
			Labels:      labels,
			Unknowns:    customFields,
		}
	}
	if i.options.IssueTypeID != "" {
		fields.Type = jira.IssueType{ID: i.options.IssueTypeID}
	}
	if i.options.ProjectID != "" {
		fields.Project = jira.Project{ID: i.options.ProjectID}
	}

	issueData := &jira.Issue{
		Fields: fields,
	}
	createdIssue, resp, err := i.jira.Issue.Create(issueData)
	if err != nil {
		var data string
		if resp != nil && resp.Body != nil {
			d, _ := io.ReadAll(resp.Body)
			data = string(d)
		}
		return nil, fmt.Errorf("%w => %s", err, data)
	}
	return getIssueResponseFromJira(createdIssue)
}

func getIssueResponseFromJira(issue *jira.Issue) (*filters.CreateIssueResponse, error) {
	parsed, err := url.Parse(issue.Self)
	if err != nil {
		return nil, err
	}
	parsed.Path = fmt.Sprintf("/browse/%s", issue.Key)
	issueURL := parsed.String()

	return &filters.CreateIssueResponse{
		IssueID:  issue.ID,
		IssueURL: issueURL,
	}, nil
}

// CreateIssue creates an issue in the tracker or updates the existing one
func (i *Integration) CreateIssue(event *output.ResultEvent) (*filters.CreateIssueResponse, error) {
	if i.options.UpdateExisting {
		issue, err := i.FindExistingIssue(event, true)
		if err != nil {
			return nil, errors.Wrap(err, "could not find existing issue")
		} else if issue.ID != "" {
			_, _, err = i.jira.Issue.AddComment(issue.ID, &jira.Comment{
				Body: format.CreateReportDescription(event, i, i.options.OmitRaw),
			})
			if err != nil {
				return nil, errors.Wrap(err, "could not add comment to existing issue")
			}
			return getIssueResponseFromJira(&issue)
		}
	}
	resp, err := i.CreateNewIssue(event)
	if err != nil {
		return nil, errors.Wrap(err, "could not create new issue")
	}
	return resp, nil
}

func (i *Integration) CloseIssue(event *output.ResultEvent) error {
	if i.options.StatusNot == "" {
		return nil
	}

	issue, err := i.FindExistingIssue(event, false)
	if err != nil {
		return err
	} else if issue.ID != "" {
		// Lazy load the transitions ID in case it's not set
		i.once.Do(func() {
			transitions, _, err := i.jira.Issue.GetTransitions(issue.ID)
			if err != nil {
				return
			}
			for _, transition := range transitions {
				if transition.Name == i.options.StatusNot {
					i.transitionID = transition.ID
					break
				}
			}
		})
		if i.transitionID == "" {
			return nil
		}
		transition := jira.CreateTransitionPayload{
			Transition: jira.TransitionPayload{
				ID: i.transitionID,
			},
		}

		_, err = i.jira.Issue.DoTransitionWithPayload(issue.ID, transition)
		if err != nil {
			return err
		}
	}
	return nil
}

// FindExistingIssue checks if the issue already exists and returns its ID
func (i *Integration) FindExistingIssue(event *output.ResultEvent, useStatus bool) (jira.Issue, error) {
	template := format.GetMatchedTemplateName(event)
	project := i.options.ProjectName
	if i.options.ProjectID != "" {
		project = i.options.ProjectID
	}
	jql := fmt.Sprintf("summary ~ \"%s\" AND summary ~ \"%s\" AND project = \"%s\"", template, event.Host, project)
	if useStatus {
		jql = fmt.Sprintf("%s AND status != \"%s\"", jql, i.options.StatusNot)
	}

	searchOptions := &jira.SearchOptions{
		MaxResults: 1, // if any issue exists, then we won't create a new one
	}

	chunk, resp, err := i.jira.Issue.Search(jql, searchOptions)
	if err != nil {
		var data string
		if resp != nil && resp.Body != nil {
			d, _ := io.ReadAll(resp.Body)
			data = string(d)
		}
		return jira.Issue{}, fmt.Errorf("%w => %s", err, data)
	}

	switch resp.Total {
	case 0:
		return jira.Issue{}, nil
	case 1:
		return chunk[0], nil
	default:
		gologger.Warning().Msgf("Discovered multiple opened issues %s for the host %s: The issue [%s] will be updated.", template, event.Host, chunk[0].ID)
		return chunk[0], nil
	}
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
