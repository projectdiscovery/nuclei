package jira

import (
	"fmt"
	"io"
	"strings"

	"github.com/andygrunwald/go-jira"
	"github.com/trivago/tgo/tcontainer"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/exporters/markdown/util"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/format"
	"github.com/projectdiscovery/retryablehttp-go"
)

type Formatter struct {
	util.MarkdownFormatter
}

func (jiraFormatter *Formatter) MakeBold(text string) string {
	return "*" + text + "*"
}

func (jiraFormatter *Formatter) CreateCodeBlock(title string, content string, _ string) string {
	return fmt.Sprintf("\n%s\n{code}\n%s\n{code}\n", jiraFormatter.MakeBold(title), content)
}

func (jiraFormatter *Formatter) CreateTable(headers []string, rows [][]string) (string, error) {
	table, err := jiraFormatter.MarkdownFormatter.CreateTable(headers, rows)
	if err != nil {
		return "", err
	}
	tableRows := strings.Split(table, "\n")
	tableRowsWithoutHeaderSeparator := append(tableRows[:1], tableRows[2:]...)
	return strings.Join(tableRowsWithoutHeaderSeparator, "\n"), nil
}

func (jiraFormatter *Formatter) CreateLink(title string, url string) string {
	return fmt.Sprintf("[%s|%s]", title, url)
}

// Integration is a client for an issue tracker integration
type Integration struct {
	Formatter
	jira    *jira.Client
	options *Options
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
	Email string `yaml:"email" json:"email" validate:"required,email"`
	// Token is the token for jira instance.
	Token string `yaml:"token" json:"token" validate:"required"`
	// ProjectName is the name of the project.
	ProjectName string `yaml:"project-name" json:"project_name" validate:"required"`
	// IssueType (optional) is the name of the created issue type
	IssueType string `yaml:"issue-type" json:"issue_type"`
	// SeverityAsLabel (optional) sends the severity as the label of the created
	// issue.
	SeverityAsLabel bool `yaml:"severity-as-label" json:"severity_as_label"`
	// Severity (optional) is the severity of the issue.
	Severity   []string              `yaml:"severity" json:"severity"`
	HttpClient *retryablehttp.Client `yaml:"-" json:"-"`
	// for each customfield specified in the configuration options
	// we will create a map of customfield name to the value
	// that will be used to create the issue
	CustomFields map[string]interface{} `yaml:"custom-fields" json:"custom_fields"`
	StatusNot    string                 `yaml:"status-not" json:"status_not"`
}

// New creates a new issue tracker integration client based on options.
func New(options *Options) (*Integration, error) {
	username := options.Email
	if !options.Cloud {
		username = options.AccountID
	}
	tp := jira.BasicAuthTransport{
		Username: username,
		Password: options.Token,
	}
	if options.HttpClient != nil {
		tp.Transport = options.HttpClient.HTTPClient.Transport
	}
	jiraClient, err := jira.NewClient(tp.Client(), options.URL)
	if err != nil {
		return nil, err
	}
	return &Integration{jira: jiraClient, options: options}, nil
}

// CreateNewIssue creates a new issue in the tracker
func (i *Integration) CreateNewIssue(event *output.ResultEvent) error {
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
					return fmt.Errorf(`couldn't iterate on nested item "%s": %s`, nestedName, nestedValue)
				}
				if strings.HasPrefix(fmtNestedValue, "$") {
					nestedValue = strings.TrimPrefix(fmtNestedValue, "$")
					switch nestedValue {
					case "CVSSMetrics":
						nestedValue = event.Info.Classification.CVSSMetrics
					case "CVEID":
						nestedValue = event.Info.Classification.CVEID
					case "CWEID":
						nestedValue = event.Info.Classification.CWEID
					case "CVSSScore":
						nestedValue = event.Info.Classification.CVSSScore
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
		Description: format.CreateReportDescription(event, i),
		Unknowns:    customFields,
		Type:        jira.IssueType{Name: i.options.IssueType},
		Project:     jira.Project{Key: i.options.ProjectName},
		Summary:     summary,
	}
	// On-prem version of Jira server does not use AccountID
	if !i.options.Cloud {
		fields = &jira.IssueFields{
			Assignee:    &jira.User{Name: i.options.AccountID},
			Description: format.CreateReportDescription(event, i),
			Type:        jira.IssueType{Name: i.options.IssueType},
			Project:     jira.Project{Key: i.options.ProjectName},
			Summary:     summary,
			Labels:      labels,
			Unknowns:    customFields,
		}
	}

	issueData := &jira.Issue{
		Fields: fields,
	}
	_, resp, err := i.jira.Issue.Create(issueData)
	if err != nil {
		var data string
		if resp != nil && resp.Body != nil {
			d, _ := io.ReadAll(resp.Body)
			data = string(d)
		}
		return fmt.Errorf("%w => %s", err, data)
	}
	return nil
}

// CreateIssue creates an issue in the tracker or updates the existing one
func (i *Integration) CreateIssue(event *output.ResultEvent) error {
	if i.options.UpdateExisting {
		issueID, err := i.FindExistingIssue(event)
		if err != nil {
			return err
		} else if issueID != "" {
			_, _, err = i.jira.Issue.AddComment(issueID, &jira.Comment{
				Body: format.CreateReportDescription(event, i),
			})
			return err
		}
	}
	return i.CreateNewIssue(event)
}

// FindExistingIssue checks if the issue already exists and returns its ID
func (i *Integration) FindExistingIssue(event *output.ResultEvent) (string, error) {
	template := format.GetMatchedTemplateName(event)
	jql := fmt.Sprintf("summary ~ \"%s\" AND summary ~ \"%s\" AND status != \"%s\"", template, event.Host, i.options.StatusNot)

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
		return "", fmt.Errorf("%w => %s", err, data)
	}

	switch resp.Total {
	case 0:
		return "", nil
	case 1:
		return chunk[0].ID, nil
	default:
		gologger.Warning().Msgf("Discovered multiple opened issues %s for the host %s: The issue [%s] will be updated.", template, event.Host, chunk[0].ID)
		return chunk[0].ID, nil
	}
}
