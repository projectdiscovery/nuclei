package jira

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/filters"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

type recordingTransport struct {
	inner http.RoundTripper
	paths []string
}

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if rt.inner == nil {
		rt.inner = http.DefaultTransport
	}
	rt.paths = append(rt.paths, req.URL.Path)
	return rt.inner.RoundTrip(req)
}

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
			Name:           "Test vulnerability",
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
		expected := "Vulnerability detected by Nuclei. Name: Test vulnerability, Severity: critical, Host: example.com"
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
		require.Contains(t, result, "Test vulnerability on example.com")
		require.Contains(t, result, "CVSS: 9.80")
		require.Contains(t, result, "⚠️ CRITICAL")
	})

	t.Run("no template syntax", func(t *testing.T) {
		result, err := integration.evaluateCustomFieldValue("plain text", buildTemplateContext(event), event)
		require.NoError(t, err)
		require.Equal(t, "plain text", result)
	})

	t.Run("template functions", func(t *testing.T) {
		// Test case conversion functions
		result, err := integration.evaluateCustomFieldValue("{{.Severity | upper}}", buildTemplateContext(event), event)
		require.NoError(t, err)
		require.Equal(t, "CRITICAL", result)

		result, err = integration.evaluateCustomFieldValue("{{.Name | lower}}", buildTemplateContext(event), event)
		require.NoError(t, err)
		require.Equal(t, "test vulnerability", result)

		result, err = integration.evaluateCustomFieldValue("{{.Name | title}}", buildTemplateContext(event), event)
		require.NoError(t, err)
		require.Equal(t, "Test Vulnerability", result)

		// Test string check functions
		result, err = integration.evaluateCustomFieldValue(`{{if contains .Name "Test"}}has-test{{else}}no-test{{end}}`, buildTemplateContext(event), event)
		require.NoError(t, err)
		require.Equal(t, "has-test", result)

		result, err = integration.evaluateCustomFieldValue(`{{if hasPrefix .Host "example"}}starts-with-example{{else}}other{{end}}`, buildTemplateContext(event), event)
		require.NoError(t, err)
		require.Equal(t, "starts-with-example", result)

		result, err = integration.evaluateCustomFieldValue(`{{if hasSuffix .Host ".com"}}ends-with-com{{else}}other{{end}}`, buildTemplateContext(event), event)
		require.NoError(t, err)
		require.Equal(t, "ends-with-com", result)

		// Test string manipulation functions
		result, err = integration.evaluateCustomFieldValue(`{{replace .Name " " "-"}}`, buildTemplateContext(event), event)
		require.NoError(t, err)
		require.Equal(t, "Test-vulnerability", result)

		result, err = integration.evaluateCustomFieldValue(`{{trimSpace " test "}}`, buildTemplateContext(event), event)
		require.NoError(t, err)
		require.Equal(t, "test", result)

		result, err = integration.evaluateCustomFieldValue(`{{trim "...test..." "."}}`, buildTemplateContext(event), event)
		require.NoError(t, err)
		require.Equal(t, "test", result)

		// Test split and join functions
		result, err = integration.evaluateCustomFieldValue(`{{join (split .Name " ") "-"}}`, buildTemplateContext(event), event)
		require.NoError(t, err)
		require.Equal(t, "Test-vulnerability", result)
	})

	t.Run("complex template with functions", func(t *testing.T) {
		templateStr := `{{.Name | upper}} on {{.Host}}
{{if contains .Name "SQL"}}SQL-INJECTION{{else if contains .Name "XSS"}}XSS-ATTACK{{else}}OTHER{{end}}
Priority: {{if eq .Severity "critical"}}{{.Severity | upper}}{{else}}{{.Severity}}{{end}}`
		result, err := integration.evaluateCustomFieldValue(templateStr, buildTemplateContext(event), event)
		require.NoError(t, err)
		require.Contains(t, result, "TEST VULNERABILITY on example.com", result)
		require.Contains(t, result, "OTHER")
		require.Contains(t, result, "CRITICAL")
	})
}

// Live test to verify SearchV2JQL hits /rest/api/3/search/jql when creds are provided via env
func TestJiraLive_SearchV2UsesJqlEndpoint(t *testing.T) {
	jiraURL := os.Getenv("JIRA_URL")
	jiraEmail := os.Getenv("JIRA_EMAIL")
	jiraAccountID := os.Getenv("JIRA_ACCOUNT_ID")
	jiraToken := os.Getenv("JIRA_TOKEN")
	jiraPAT := os.Getenv("JIRA_PAT")
	jiraProjectName := os.Getenv("JIRA_PROJECT_NAME")
	jiraProjectID := os.Getenv("JIRA_PROJECT_ID")
	jiraStatusNot := os.Getenv("JIRA_STATUS_NOT")
	jiraCloud := os.Getenv("JIRA_CLOUD")

	if jiraURL == "" || (jiraPAT == "" && jiraToken == "") || (jiraEmail == "" && jiraAccountID == "") || (jiraProjectName == "" && jiraProjectID == "") {
		t.Skip("live Jira test skipped: missing JIRA_* env vars")
	}

	statusNot := jiraStatusNot
	if statusNot == "" {
		statusNot = "Done"
	}

	isCloud := !strings.EqualFold(jiraCloud, "false") && jiraCloud != "0"

	rec := &recordingTransport{}
	rc := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	rc.HTTPClient.Transport = rec

	opts := &Options{
		Cloud:               isCloud,
		URL:                 jiraURL,
		Email:               jiraEmail,
		AccountID:           jiraAccountID,
		Token:               jiraToken,
		PersonalAccessToken: jiraPAT,
		ProjectName:         jiraProjectName,
		ProjectID:           jiraProjectID,
		IssueType:           "Task",
		StatusNot:           statusNot,
		HttpClient:          rc,
	}

	integration, err := New(opts)
	require.NoError(t, err)

	event := &output.ResultEvent{
		Host: "example.com",
		Info: model.Info{
			Name:           "Nuclei Live Verify",
			SeverityHolder: severity.Holder{Severity: severity.Low},
		},
	}

	_, _ = integration.FindExistingIssue(event, true)

	var hitSearchV2 bool
	for _, p := range rec.paths {
		if strings.HasSuffix(p, "/rest/api/3/search/jql") {
			hitSearchV2 = true
			break
		}
	}
	require.True(t, hitSearchV2, "expected client to call /rest/api/3/search/jql, got paths: %v", rec.paths)
}
