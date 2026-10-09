package linear

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

type fakeLinear struct {
	mu         sync.Mutex
	stateType  string
	mutations  []map[string]any
	stateQuery int
}

func (f *fakeLinear) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.Contains(body.Query, "workflowStates"):
		f.stateQuery++
		_, _ = w.Write([]byte(`{"data":{"workflowStates":{"nodes":[{"id":"state-late","position":9},{"id":"state-done","position":2}]}}}`))
	case strings.Contains(body.Query, "issueUpdate"):
		f.mutations = append(f.mutations, body.Variables)
		_, _ = w.Write([]byte(`{"data":{"issueUpdate":{"lastSyncId":1}}}`))
	default:
		_, _ = w.Write([]byte(`{"data":{"issues":{"nodes":[{"id":"issue-1","title":"t","identifier":"ENG-1","state":{"name":"Todo","type":"` + f.stateType + `"},"url":"u"}]}}}`))
	}
}

func newTestIntegration(t *testing.T, fake *fakeLinear) *Integration {
	t.Helper()
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)

	integration, err := New(&Options{APIKey: "key", TeamID: "team-1"})
	require.NoError(t, err)
	integration.url = server.URL
	return integration
}

func testEvent() *output.ResultEvent {
	return &output.ResultEvent{TemplateID: "tpl", Host: "example.com", Info: model.Info{Name: "finding"}}
}

func TestCloseIssueMovesToDiscoveredCompletedState(t *testing.T) {
	fake := &fakeLinear{stateType: "unstarted"}
	integration := newTestIntegration(t, fake)

	require.NoError(t, integration.CloseIssue(testEvent()))
	require.NoError(t, integration.CloseIssue(testEvent()))

	require.Len(t, fake.mutations, 2)
	require.Equal(t, 1, fake.stateQuery)
	require.Equal(t, "issue-1", fake.mutations[0]["issueID"])
	require.Equal(t, map[string]any{"stateId": "state-done"}, fake.mutations[0]["issueUpdateInput"])
}

func TestCloseIssueUsesConfiguredClosedStateID(t *testing.T) {
	fake := &fakeLinear{stateType: "started"}
	integration := newTestIntegration(t, fake)
	integration.options.ClosedStateID = "configured"

	require.NoError(t, integration.CloseIssue(testEvent()))

	require.Len(t, fake.mutations, 1)
	require.Zero(t, fake.stateQuery)
	require.Equal(t, map[string]any{"stateId": "configured"}, fake.mutations[0]["issueUpdateInput"])
}

func TestCloseIssueSkipsAlreadyClosedIssue(t *testing.T) {
	for _, stateType := range []string{"completed", "canceled"} {
		fake := &fakeLinear{stateType: stateType}
		integration := newTestIntegration(t, fake)

		require.NoError(t, integration.CloseIssue(testEvent()))
		require.Empty(t, fake.mutations, stateType)
	}
}
