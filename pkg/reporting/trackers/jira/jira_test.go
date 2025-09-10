package jira

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/filters"
	"github.com/stretchr/testify/require"
)

func TestLinkCreation(t *testing.T) {
	jiraIntegration := &Integration{}
	link := jiraIntegration.CreateLink("ProjectDiscovery", "https://projectdiscovery.io")
	require.Equal(t, "[ProjectDiscovery|https://projectdiscovery.io]", link)
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
| a | b |
| c |  |
| d | e |
`
	require.Equal(t, expected, table)
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

func TestTemplateEvaluation(t *testing.T) {
	event := &output.ResultEvent{
		Host: "example.com",
		Info: model.Info{
			Name:           "Test Vulnerability",
			SeverityHolder: severity.Holder{Severity: severity.Critical},
			Classification: &model.Classification{
				CVSSScore:   9.8,
				CVEID:       stringslice.StringSlice{Value: []string{"CVE-2023-1234"}},
				CWEID:       stringslice.StringSlice{Value: []string{"CWE-79"}},
				CVSSMetrics: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			},
		},
	}

	integration := &Integration{}

	t.Run("conditional template", func(t *testing.T) {
		templateStr := `{{if eq .Severity "critical"}}11187{{else if eq .Severity "high"}}11186{{else if eq .Severity "medium"}}11185{{else}}11184{{end}}`
		result, err := integration.evaluateCustomFieldValue(templateStr, buildTemplateContext(event), event)
		require.NoError(t, err)
		require.Equal(t, "11187", result)
	})

	t.Run("freeform description template", func(t *testing.T) {
		templateStr := `Vulnerability detected by Nuclei. Name: {{.Name}}, Severity: {{.Severity}}, Host: {{.Host}}`
		result, err := integration.evaluateCustomFieldValue(templateStr, buildTemplateContext(event), event)
		require.NoError(t, err)
		expected := "Vulnerability detected by Nuclei. Name: Test Vulnerability, Severity: critical, Host: example.com"
		require.Equal(t, expected, result)
	})

	t.Run("legacy variable syntax", func(t *testing.T) {
		result, err := integration.evaluateCustomFieldValue("$Severity", buildTemplateContext(event), event)
		require.NoError(t, err)
		require.Equal(t, "critical", result)

		result, err = integration.evaluateCustomFieldValue("$Host", buildTemplateContext(event), event)
		require.NoError(t, err)
		require.Equal(t, "example.com", result)
	})

	t.Run("complex template with conditionals", func(t *testing.T) {
		templateStr := `{{.Name}} on {{.Host}}
{{if .CVSSScore}}CVSS: {{.CVSSScore}}{{end}}
{{if eq .Severity "critical"}}⚠️ CRITICAL{{else}}Standard{{end}}`
		result, err := integration.evaluateCustomFieldValue(templateStr, buildTemplateContext(event), event)
		require.NoError(t, err)
		require.Contains(t, result, "Test Vulnerability on example.com")
		require.Contains(t, result, "CVSS: 9.80")
		require.Contains(t, result, "⚠️ CRITICAL")
	})

	t.Run("no template syntax", func(t *testing.T) {
		result, err := integration.evaluateCustomFieldValue("plain text", buildTemplateContext(event), event)
		require.NoError(t, err)
		require.Equal(t, "plain text", result)
	})
}
