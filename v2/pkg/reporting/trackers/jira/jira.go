package jira

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"strings"

	jira "github.com/andygrunwald/go-jira"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/format"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Integration is a client for a issue tracker integration
type Integration struct {
	jira    *jira.Client
	options *Options
}

// Options contains the configuration options for jira client
type Options struct {
	// Cloud value is set to true when Jira cloud is used
	Cloud bool `yaml:"cloud"`
	// URL is the URL of the jira server
	URL string `yaml:"url"`
	// AccountID is the accountID of the jira user.
	AccountID string `yaml:"account-id"`
	// Email is the email of the user for jira instance
	Email string `yaml:"email"`
	// Token is the token for jira instance.
	Token string `yaml:"token"`
	// ProjectName is the name of the project.
	ProjectName string `yaml:"project-name"`
	// IssueType is the name of the created issue type
	IssueType string `yaml:"issue-type"`
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
	jiraClient, err := jira.NewClient(tp.Client(), options.URL)
	if err != nil {
		return nil, err
	}
	return &Integration{jira: jiraClient, options: options}, nil
}

// CreateIssue creates an issue in the tracker
func (i *Integration) CreateIssue(event *output.ResultEvent) error {
	summary := format.Summary(event)

	fields := &jira.IssueFields{
		Assignee:    &jira.User{AccountID: i.options.AccountID},
		Reporter:    &jira.User{AccountID: i.options.AccountID},
		Description: jiraFormatDescription(event),
		Type:        jira.IssueType{Name: i.options.IssueType},
		Project:     jira.Project{Key: i.options.ProjectName},
		Summary:     summary,
	}
	// On-prem version of Jira server does not use AccountID
	if !i.options.Cloud {
		fields = &jira.IssueFields{
			Assignee:    &jira.User{Name: i.options.AccountID},
			Description: jiraFormatDescription(event),
			Type:        jira.IssueType{Name: i.options.IssueType},
			Project:     jira.Project{Key: i.options.ProjectName},
			Summary:     summary,
		}
	}

	issueData := &jira.Issue{
		Fields: fields,
	}
	_, resp, err := i.jira.Issue.Create(issueData)
	if err != nil {
		var data string
		if resp != nil && resp.Body != nil {
			d, _ := ioutil.ReadAll(resp.Body)
			data = string(d)
		}
		return fmt.Errorf("%s => %s", err, data)
	}
	return nil
}

// jiraFormatDescription formats a short description of the generated
// event by the nuclei scanner in Jira format.
func jiraFormatDescription(event *output.ResultEvent) string {
	template := format.GetMatchedTemplate(event)

	builder := &bytes.Buffer{}
	builder.WriteString("*Details*: *")
	builder.WriteString(template)
	builder.WriteString("* ")
	builder.WriteString(" matched at ")
	builder.WriteString(event.Host)
	builder.WriteString("\n\n*Protocol*: ")
	builder.WriteString(strings.ToUpper(event.Type))
	builder.WriteString("\n\n*Full URL*: ")
	builder.WriteString(event.Matched)
	builder.WriteString("\n\n*Timestamp*: ")
	builder.WriteString(event.Timestamp.Format("Mon Jan 2 15:04:05 -0700 MST 2006"))
	builder.WriteString("\n\n*Template Information*\n\n| Key | Value |\n")
	for k, v := range event.Info {
		if k == "reference" {
			continue
		}
		builder.WriteString(fmt.Sprintf("| %s | %s |\n", k, v))
	}
	builder.WriteString("\n*Request*\n\n{code}\n")
	builder.WriteString(event.Request)
	builder.WriteString("\n{code}\n\n*Response*\n\n{code}\n")
	// If the response is larger than 5 kb, truncate it before writing.
	if len(event.Response) > 5*1024 {
		builder.WriteString(event.Response[:5*1024])
		builder.WriteString(".... Truncated ....")
	} else {
		builder.WriteString(event.Response)
	}
	builder.WriteString("\n{code}\n\n")

	if len(event.ExtractedResults) > 0 || len(event.Metadata) > 0 {
		builder.WriteString("\n*Extra Information*\n\n")
		if len(event.ExtractedResults) > 0 {
			builder.WriteString("*Extracted results*:\n\n")
			for _, v := range event.ExtractedResults {
				builder.WriteString("- ")
				builder.WriteString(v)
				builder.WriteString("\n")
			}
			builder.WriteString("\n")
		}
		if len(event.Metadata) > 0 {
			builder.WriteString("*Metadata*:\n\n")
			for k, v := range event.Metadata {
				builder.WriteString("- ")
				builder.WriteString(k)
				builder.WriteString(": ")
				builder.WriteString(types.ToString(v))
				builder.WriteString("\n")
			}
			builder.WriteString("\n")
		}
	}
	if event.Interaction != nil {
		builder.WriteString("*Interaction Data*\n---\n")
		builder.WriteString(event.Interaction.Protocol)
		if event.Interaction.QType != "" {
			builder.WriteString(" (")
			builder.WriteString(event.Interaction.QType)
			builder.WriteString(")")
		}
		builder.WriteString(" Interaction from ")
		builder.WriteString(event.Interaction.RemoteAddress)
		builder.WriteString(" at ")
		builder.WriteString(event.Interaction.UniqueID)

		if event.Interaction.RawRequest != "" {
			builder.WriteString("\n\n*Interaction Request*\n\n{code}\n")
			builder.WriteString(event.Interaction.RawRequest)
			builder.WriteString("\n{code}\n")
		}
		if event.Interaction.RawResponse != "" {
			builder.WriteString("\n*Interaction Response*\n\n{code}\n")
			builder.WriteString(event.Interaction.RawResponse)
			builder.WriteString("\n{code}\n")
		}
	}
	if d, ok := event.Info["reference"]; ok {
		builder.WriteString("\nReference: \n")

		switch v := d.(type) {
		case string:
			if !strings.HasPrefix(v, "-") {
				builder.WriteString("- ")
			}
			builder.WriteString(v)
		case []interface{}:
			slice := types.ToStringSlice(v)
			for i, item := range slice {
				builder.WriteString("- ")
				builder.WriteString(item)
				if len(slice)-1 != i {
					builder.WriteString("\n")
				}
			}
		}
	}
	builder.WriteString("\n---\nGenerated by [Nuclei|https://github.com/projectdiscovery/nuclei]")
	data := builder.String()
	return data
}
