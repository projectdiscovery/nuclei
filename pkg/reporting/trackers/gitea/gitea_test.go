package gitea

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

const testIssueTitle = "Test finding (template-id) found on example.com"

type issueRequest struct {
	Page    string
	Limit   string
	State   string
	Keyword string
}

type fakeGitea struct {
	server       *httptest.Server
	requests     []issueRequest
	comments     []int64
	created      int
	issueHandler func(http.ResponseWriter, *http.Request, issueRequest)
}

func newFakeGitea(t *testing.T, issueHandler func(http.ResponseWriter, *http.Request, issueRequest)) (*Integration, *fakeGitea) {
	t.Helper()

	fake := &fakeGitea{issueHandler: issueHandler}
	fake.server = httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
	t.Cleanup(fake.server.Close)

	integration, err := New(&Options{
		BaseURL:             fake.server.URL,
		Token:               "test-token",
		ProjectOwner:        "owner",
		ProjectName:         "repo",
		DuplicateIssueCheck: true,
	})
	require.NoError(t, err)
	return integration, fake
}

func (f *fakeGitea) serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/version"):
		_, _ = w.Write([]byte(`{"version":"1.21.0"}`))
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/labels"):
		_, _ = w.Write([]byte("[]"))
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issues"):
		query := r.URL.Query()
		request := issueRequest{
			Page:    query.Get("page"),
			Limit:   query.Get("limit"),
			State:   query.Get("state"),
			Keyword: query.Get("q"),
		}
		f.requests = append(f.requests, request)
		f.issueHandler(w, r, request)
	case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/comments"):
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		issueNumber, _ := strconv.ParseInt(parts[len(parts)-2], 10, 64)
		f.comments = append(f.comments, issueNumber)
		_, _ = w.Write([]byte(`{"id":1}`))
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/issues"):
		f.created++
		_, _ = w.Write([]byte(`{"number":99,"title":"created","url":"https://gitea.test/issues/99"}`))
	default:
		http.NotFound(w, r)
	}
}

func writeIssuePage(w http.ResponseWriter, issues ...map[string]any) {
	_ = json.NewEncoder(w).Encode(issues)
}

func TestCreateIssueFollowsLinkAfterCappedPageAndComments(t *testing.T) {
	var server *httptest.Server
	integration, fake := newFakeGitea(t, func(w http.ResponseWriter, r *http.Request, request issueRequest) {
		if request.Page == "1" {
			// Gitea may return only 50 items despite a requested limit of 100.
			w.Header().Set("Link", fmt.Sprintf("<%s%s?limit=100&page=2&state=all>; rel=\"next\"", server.URL, r.URL.Path))
			issues := make([]map[string]any, 50)
			for index := range issues {
				issues[index] = map[string]any{"number": index + 1, "title": "unrelated issue"}
			}
			writeIssuePage(w, issues...)
			return
		}
		writeIssuePage(w, map[string]any{"number": 42, "title": testIssueTitle, "url": "https://gitea.test/issues/42"})
	})
	server = fake.server

	response, err := integration.CreateIssue(testGiteaEvent())
	require.NoError(t, err)
	require.Equal(t, "42", response.IssueID)
	require.Equal(t, "https://gitea.test/issues/42", response.IssueURL)
	require.Equal(t, []int64{42}, fake.comments)
	require.Zero(t, fake.created)
	require.Equal(t, []string{"1", "2"}, []string{fake.requests[0].Page, fake.requests[1].Page})
	for _, request := range fake.requests {
		require.Equal(t, "100", request.Limit)
		require.Equal(t, "all", request.State)
		require.Empty(t, request.Keyword)
	}
}

func TestFindIssueByTitleRespectsMaxPages(t *testing.T) {
	var server *httptest.Server
	integration, fake := newFakeGitea(t, func(w http.ResponseWriter, r *http.Request, request issueRequest) {
		w.Header().Set("Link", fmt.Sprintf("<%s%s?page=2>; rel=\"next\"", server.URL, r.URL.Path))
		writeIssuePage(w, map[string]any{"number": 1, "title": "unrelated"})
	})
	server = fake.server
	integration.options.DuplicateIssueMaxPages = 1

	issue, err := integration.findIssueByTitle(testIssueTitle)
	require.NoError(t, err)
	require.Nil(t, issue)
	require.Len(t, fake.requests, 1)
	require.Equal(t, "1", fake.requests[0].Page)
}

func TestFindIssueByTitleStopsWhenLinkHeaderHasNoNextPage(t *testing.T) {
	integration, fake := newFakeGitea(t, func(w http.ResponseWriter, _ *http.Request, _ issueRequest) {
		writeIssuePage(w, map[string]any{"number": 1, "title": "unrelated"})
	})

	issue, err := integration.findIssueByTitle(testIssueTitle)
	require.NoError(t, err)
	require.Nil(t, issue)
	require.Len(t, fake.requests, 1)
}

func testGiteaEvent() *output.ResultEvent {
	return &output.ResultEvent{
		TemplateID: "template-id",
		Host:       "example.com",
		Info:       model.Info{Name: "Test finding"},
	}
}
