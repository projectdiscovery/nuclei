package jira

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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

func TestCloseIssueUsesServerSearchResult(t *testing.T) {
	transitionCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/search"):
			_, _ = w.Write([]byte(`{"issues":[{"id":"18866","key":"TEST-1","fields":{"status":{"name":"Open"}}}]}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/search/jql"):
			http.Error(w, "", http.StatusForbidden)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/transitions"):
			_, _ = w.Write([]byte(`{"transitions":[{"id":"5","to":{"name":"Done"}}]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/transitions"):
			transitionCalls++
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected endpoint", http.StatusNotFound)
		}
	}))
	defer server.Close()

	integration, err := New(&Options{URL: server.URL, AccountID: "test", Token: "test", ProjectName: "TEST", StatusNot: "Done"})
	require.NoError(t, err)
	err = integration.CloseIssue(&output.ResultEvent{TemplateID: "pdcp-verify", Host: "example.test", Info: model.Info{Name: "Test issue"}})
	require.NoError(t, err)
	require.Equal(t, 1, transitionCalls)
}

func TestCloseIssueSearchesConfiguredProjectWhenEventHasAnotherJiraID(t *testing.T) {
	searchCalls, transitionCalls := 0, 0
	searchJQL := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/search"):
			searchCalls++
			searchJQL = r.URL.Query().Get("jql")
			_, _ = w.Write([]byte(`{"issues":[{"id":"123","key":"TEST-1","fields":{"status":{"name":"Open"}}}]}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/search/jql"):
			http.Error(w, "", http.StatusForbidden)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issue/123/transitions"):
			_, _ = w.Write([]byte(`{"transitions":[{"id":"5","to":{"name":"Done"}}]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/issue/123/transitions"):
			transitionCalls++
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected endpoint", http.StatusNotFound)
		}
	}))
	defer server.Close()

	integration, err := New(&Options{URL: server.URL, AccountID: "test", Token: "test", ProjectName: "TEST", StatusNot: "Done"})
	require.NoError(t, err)
	err = integration.CloseIssue(&output.ResultEvent{
		TemplateID: "pdcp-verify",
		Host:       "example.test",
		IssueTrackers: map[string]output.IssueTrackerMetadata{
			"jira": {IssueID: "18866"},
		},
	})
	require.NoError(t, err)
	require.Equal(t, 1, searchCalls)
	require.Contains(t, searchJQL, `project = "TEST"`)
	require.Equal(t, 1, transitionCalls)
}

func TestCloseIssueReportsTransitionLookupFailure(t *testing.T) {
	transitionLookups := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/search"):
			_, _ = w.Write([]byte(`{"issues":[{"id":"18866","key":"TEST-1","fields":{"status":{"name":"Open"}}}]}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/search/jql"):
			http.Error(w, "", http.StatusForbidden)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/transitions"):
			transitionLookups++
			http.Error(w, "", http.StatusForbidden)
		default:
			http.Error(w, "unexpected endpoint", http.StatusNotFound)
		}
	}))
	defer server.Close()

	integration, err := New(&Options{URL: server.URL, AccountID: "test", Token: "test", ProjectName: "TEST", StatusNot: "Done"})
	require.NoError(t, err)
	err = integration.CloseIssue(&output.ResultEvent{TemplateID: "pdcp-verify", Host: "example.test", Info: model.Info{Name: "Test issue"}})
	require.ErrorContains(t, err, fmt.Sprint(http.StatusForbidden))
	require.Equal(t, 1, transitionLookups)
}

func TestCloseIssueWithoutTargetTransition(t *testing.T) {
	for _, tc := range []struct {
		status  string
		wantErr bool
	}{
		{status: "Open", wantErr: true},
		{status: "Done", wantErr: false},
	} {
		t.Run(tc.status, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/search"):
					_, _ = w.Write([]byte(`{"issues":[{"id":"18866","key":"TEST-1","fields":{"status":{"name":"Open"}}}]}`))
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/transitions"):
					_, _ = w.Write([]byte(`{"transitions":[]}`))
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issue/18866"):
					_, _ = fmt.Fprintf(w, `{"fields":{"status":{"name":%q}}}`, tc.status)
				default:
					http.Error(w, "unexpected endpoint", http.StatusNotFound)
				}
			}))
			defer server.Close()

			integration, err := New(&Options{URL: server.URL, AccountID: "test", Token: "test", StatusNot: "Done"})
			require.NoError(t, err)
			err = integration.CloseIssue(&output.ResultEvent{IssueTrackers: map[string]output.IssueTrackerMetadata{
				"jira": {IssueID: "18866"},
			}})
			if tc.wantErr {
				require.ErrorContains(t, err, "no transition")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

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
