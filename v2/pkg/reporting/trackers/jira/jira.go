package jira

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/andygrunwald/go-jira"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/format"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Integration is a client for an issue tracker integration
type Integration struct {
	jira    *jira.Client
	options *Options
}

// Options contains the configuration options for jira client
type Options struct {
	// Cloud value is set to true when Jira cloud is used
	Cloud bool `yaml:"cloud"`
	// UpdateExisting value if true, the existing opened issue is updated
	UpdateExisting bool `yaml:"update-existing"`
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

// CreateNewIssue creates a new issue in the tracker
func (i *Integration) CreateNewIssue(event *output.ResultEvent) error {
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

// CreateIssue creates an issue in the tracker or updates the existing one
func (i *Integration) CreateIssue(event *output.ResultEvent) error {
	if i.options.UpdateExisting {
		issueID, err := i.FindExistingIssue(event)
		if err != nil {
			return err
		} else if issueID != "" {
			_, _, err = i.jira.Issue.AddComment(issueID, &jira.Comment{
				Body: jiraFormatDescription(event),
			})
			return err
		}
	}
	return i.CreateNewIssue(event)
}

// FindExistingIssue checks if the issue already exists and returns its ID
func (i *Integration) FindExistingIssue(event *output.ResultEvent) (string, error) {
	template := format.GetMatchedTemplate(event)
	jql := fmt.Sprintf("summary ~ \"%s\" AND summary ~ \"%s\" AND status = \"Open\"", template, event.Host)

	searchOptions := &jira.SearchOptions{
		MaxResults: 1, // if any issue exists, then we won't create a new one
	}

	chunk, resp, err := i.jira.Issue.Search(jql, searchOptions)
	if err != nil {
		var data string
		if resp != nil && resp.Body != nil {
			d, _ := ioutil.ReadAll(resp.Body)
			data = string(d)
		}
		return "", fmt.Errorf("%s => %s", err, data)
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

// jiraFormatDescription formats a short description of the generated
// event by the nuclei scanner in Jira format.
func jiraFormatDescription(event *output.ResultEvent) string { // TODO remove the code duplication: format.go <-> jira.go
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
	builder.WriteString(format.ToMarkdownTableString(&event.Info))

	builder.WriteString("\n*Request*\n\n{code}\n")
	builder.WriteString(event.Request)
	builder.WriteString("\n{code}\n")

	builder.WriteString("\n*Response*\n\n{code}\n")
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

	reference := event.Info.Reference
	if !reference.IsEmpty() {
		builder.WriteString("\nReferences: \n")

		referenceSlice := reference.ToSlice()
		for i, item := range referenceSlice {
			builder.WriteString("- ")
			builder.WriteString(item)
			if len(referenceSlice)-1 != i {
				builder.WriteString("\n")
			}
		}
	}
	builder.WriteString(fmt.Sprintf("\n---\nGenerated by [Nuclei v%s](https://github.com/projectdiscovery/nuclei)", config.Version))
	data := builder.String()
	return data
}
