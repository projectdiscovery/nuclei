package jira

import (
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/format"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/filters"
	"github.com/stretchr/testify/require"
)

func TestLinkCreation(t *testing.T) {
	jiraIntegration := &Integration{}
	link := jiraIntegration.CreateLink("ProjectDiscovery", "https://projectdiscovery.io")
	require.Equal(t, "[ProjectDiscovery](https://projectdiscovery.io)", link)
}

func TestLinkCreationWithSpecialCharacters(t *testing.T) {
	jiraIntegration := &Integration{}

	link := jiraIntegration.CreateLink("Nuclei [v3.4.4]", "https://github.com/projectdiscovery/nuclei")
	expected := "[Nuclei [v3.4.4]](https://github.com/projectdiscovery/nuclei)"
	require.Equal(t, expected, link)

	require.NotContains(t, link, "%5D")
	require.NotContains(t, link, "%5B")
}

func TestHorizontalLineCreation(t *testing.T) {
	jiraIntegration := &Integration{}
	horizontalLine := jiraIntegration.CreateHorizontalLine()
	require.True(t, strings.Contains(horizontalLine, "----"))
}

func TestTableCreation(t *testing.T) {
	jiraIntegration := &Integration{}

	table, err := jiraIntegration.CreateTable([]string{"key", "value"}, [][]string{
		{"a", "b"},
		{"c"},
		{"d", "e"},
	})

	require.Nil(t, err)
	expected := `| key | value |
|-----------|-----------|
| a | b |
| c |  |
| d | e |
`
	require.Equal(t, expected, table)
}

func TestTableCreationWithComplexData(t *testing.T) {
	jiraIntegration := &Integration{}

	table, err := jiraIntegration.CreateTable([]string{"Key", "Value"}, [][]string{
		{"Name", "GraphQL CSRF / GET method"},
		{"Authors", "Dolev Farhi"},
		{"Tags", "graphql, misconfig"},
		{"Severity", "info"},
	})

	require.Nil(t, err)

	require.Contains(t, table, "| Key | Value |")
	require.Contains(t, table, "|-----------|-----------|")
	require.Contains(t, table, "| Name | GraphQL CSRF / GET method |")

	require.Contains(t, table, "GraphQL CSRF")
	require.NotContains(t, table, "| ame |")
	require.NotContains(t, table, "| uthors |")
}

func TestFormatLineBreaks(t *testing.T) {
	jiraIntegration := &Integration{}

	input := "Line 1\nLine 2\nLine 3"
	result := jiraIntegration.FormatLineBreaks(input)
	expected := "Line 1\\\\Line 2\\\\Line 3"

	require.Equal(t, expected, result)

	require.NotContains(t, result, "<br>")
}

func TestFormatLineBreaksWithMultipleBreaks(t *testing.T) {
	jiraIntegration := &Integration{}

	input := "Cross Site Request Forgery happens when an external website gains ability to make API calls impersonating an user.\nAllowing API calls through GET requests can lead to CSRF attacks."
	result := jiraIntegration.FormatLineBreaks(input)
	expected := "Cross Site Request Forgery happens when an external website gains ability to make API calls impersonating an user.\\\\Allowing API calls through GET requests can lead to CSRF attacks."

	require.Equal(t, expected, result)
}

func TestCompleteReportGeneration(t *testing.T) {
	jiraIntegration := &Integration{}

	event := &output.ResultEvent{
		TemplateID: "graphql-get-method",
		Info: model.Info{
			Name:           "GraphQL CSRF / GET method",
			Authors:        stringslice.StringSlice{Value: []string{"Dolev Farhi"}},
			Tags:           stringslice.StringSlice{Value: []string{"graphql", "misconfig"}},
			SeverityHolder: severity.Holder{Severity: severity.Info},
			Description:    "Cross Site Request Forgery happens when an external website gains ability to make API calls impersonating an user.\nAllowing API calls through GET requests can lead to CSRF attacks.",
			Reference: stringslice.NewRawStringSlice([]string{
				"https://graphql.org/learn/serving-over-http/#get-request",
				"https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application",
			}),
		},
		Host:      "example.com",
		Matched:   "example.com/graphql",
		Timestamp: time.Date(2025, 5, 31, 12, 0, 0, 0, time.UTC),
		Type:      "http",
	}

	description := format.CreateReportDescription(event, jiraIntegration, false)

	require.Contains(t, description, "*Details*: *graphql-get-method* matched at example.com")
	require.Contains(t, description, "*Protocol*: HTTP")
	require.Contains(t, description, "*Template Information*")

	require.Contains(t, description, "| Key | Value |")
	require.Contains(t, description, "|-----------|-----------|")
	require.Contains(t, description, "| Name | GraphQL CSRF / GET method |")

	require.Contains(t, description, "impersonating an user.\\\\Allowing API calls")
	require.NotContains(t, description, "<br>")

	require.Contains(t, description, "[Nuclei")
	require.Contains(t, description, "](https://github.com/projectdiscovery/nuclei)")

	require.NotContains(t, description, "%5D")
	require.NotContains(t, description, "%5B")

	require.Contains(t, description, "References:")
	require.Contains(t, description, "https://graphql.org/learn/serving-over-http/#get-request")
}

func TestReportWithCVELinks(t *testing.T) {
	jiraIntegration := &Integration{}

	event := &output.ResultEvent{
		TemplateID: "test-cve",
		Info: model.Info{
			Name:           "Test CVE Template",
			Authors:        stringslice.StringSlice{Value: []string{"test-author"}},
			Tags:           stringslice.StringSlice{Value: []string{"cve", "test"}},
			SeverityHolder: severity.Holder{Severity: severity.High},
			Description:    "Test template with CVE links",
			Classification: &model.Classification{
				CVEID:       stringslice.StringSlice{Value: []string{"CVE-2021-44228"}},
				CWEID:       stringslice.StringSlice{Value: []string{"CWE-502"}},
				CVSSMetrics: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
				CVSSScore:   10.0,
			},
		},
		Host:      "example.com",
		Matched:   "example.com/test",
		Timestamp: time.Date(2025, 5, 31, 12, 0, 0, 0, time.UTC),
		Type:      "http",
	}

	description := format.CreateReportDescription(event, jiraIntegration, false)

	require.Contains(t, description, "[CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228)")
	require.Contains(t, description, "[CWE-502](https://cwe.mitre.org/data/definitions/502.html)")
	require.Contains(t, description, "[CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)")

	require.NotContains(t, description, "|https://")

	require.NotContains(t, description, "%5D")
}

func Test_ShouldFilter_Tracker(t *testing.T) {
	jiraIntegration := &Integration{
		options: &Options{AllowList: &filters.Filter{
			Severities: severity.Severities{severity.Critical},
		}},
	}

	require.False(t, jiraIntegration.ShouldFilter(&output.ResultEvent{Info: model.Info{
		SeverityHolder: severity.Holder{Severity: severity.Info},
	}}))
	require.True(t, jiraIntegration.ShouldFilter(&output.ResultEvent{Info: model.Info{
		SeverityHolder: severity.Holder{Severity: severity.Critical},
	}}))

	t.Run("deny-list", func(t *testing.T) {
		jiraIntegration := &Integration{
			options: &Options{DenyList: &filters.Filter{
				Severities: severity.Severities{severity.Critical},
			}},
		}

		require.True(t, jiraIntegration.ShouldFilter(&output.ResultEvent{Info: model.Info{
			SeverityHolder: severity.Holder{Severity: severity.Info},
		}}))
		require.False(t, jiraIntegration.ShouldFilter(&output.ResultEvent{Info: model.Info{
			SeverityHolder: severity.Holder{Severity: severity.Critical},
		}}))
	})
}
