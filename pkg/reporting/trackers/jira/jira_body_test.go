package jira

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// bodyTracker is a transport that records whether every response body it
// hands out gets closed.
type bodyTracker struct {
	mu     sync.Mutex
	bodies []*trackedBody
}

type trackedBody struct {
	io.ReadCloser
	path   string
	closed bool
}

func (b *trackedBody) Close() error {
	b.closed = true
	return b.ReadCloser.Close()
}

func (t *bodyTracker) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	body := &trackedBody{ReadCloser: resp.Body, path: req.Method + " " + req.URL.Path}
	t.mu.Lock()
	t.bodies = append(t.bodies, body)
	t.mu.Unlock()
	resp.Body = body
	return resp, nil
}

func (t *bodyTracker) requireAllClosed(tb testing.TB) {
	tb.Helper()
	t.mu.Lock()
	defer t.mu.Unlock()
	require.NotEmpty(tb, t.bodies)
	for _, body := range t.bodies {
		require.Truef(tb, body.closed, "response body of %s was not closed", body.path)
	}
}

func newTrackedIntegration(t *testing.T, serverURL string, cloud bool) (*Integration, *bodyTracker) {
	t.Helper()
	tracker := &bodyTracker{}
	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	client.HTTPClient.Transport = tracker
	integration, err := New(&Options{
		URL:         serverURL,
		Cloud:       cloud,
		AccountID:   "test",
		Email:       "test@example.test",
		Token:       "test",
		ProjectName: "TEST",
		IssueType:   "Bug",
		StatusNot:   "Done",
		HttpClient:  client,
	})
	require.NoError(t, err)
	return integration, tracker
}

func TestCloseIssueByIDClosesTransitionResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/issue/10001/transitions"):
			_, _ = w.Write([]byte(`{"transitions":[{"id":"5","to":{"name":"Done"}}]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/issue/10001/transitions"):
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected endpoint", http.StatusNotFound)
		}
	}))
	defer server.Close()

	integration, tracker := newTrackedIntegration(t, server.URL, false)
	require.NoError(t, integration.CloseIssueByID("10001"))
	tracker.requireAllClosed(t)
}

func TestCreateNewIssueClosesErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rest/api/2/issue") {
			http.Error(w, `{"errorMessages":["Field 'priority' cannot be set"]}`, http.StatusBadRequest)
			return
		}
		http.Error(w, "unexpected endpoint", http.StatusNotFound)
	}))
	defer server.Close()

	integration, tracker := newTrackedIntegration(t, server.URL, false)
	_, err := integration.CreateNewIssue(&output.ResultEvent{TemplateID: "test", Host: "example.test", Info: model.Info{Name: "Test issue"}})
	require.ErrorContains(t, err, "cannot be set")
	tracker.requireAllClosed(t)
}

func TestFindExistingIssueCloudClosesErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/rest/api/3/search/jql") {
			http.Error(w, "jql rejected", http.StatusBadRequest)
			return
		}
		http.Error(w, "unexpected endpoint", http.StatusNotFound)
	}))
	defer server.Close()

	integration, tracker := newTrackedIntegration(t, server.URL, true)
	_, err := integration.FindExistingIssue(&output.ResultEvent{TemplateID: "test", Host: "example.test", Info: model.Info{Name: "Test issue"}}, true)
	require.ErrorContains(t, err, "jql rejected")
	tracker.requireAllClosed(t)
}
