package linear

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

type fakeLinear struct {
	mu            sync.Mutex
	stateType     string
	rejectUpdates bool
	holdStates    chan struct{}
	mutations     []map[string]any
	searches      []map[string]any
	stateQuery    int
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
		if f.holdStates != nil {
			f.mu.Unlock()
			<-f.holdStates
			f.mu.Lock()
		}
		_, _ = w.Write([]byte(`{"data":{"workflowStates":{"nodes":[{"id":"state-late","position":9},{"id":"state-done","position":2}]}}}`))
	case strings.Contains(body.Query, "issueUpdate"):
		f.mutations = append(f.mutations, body.Variables)
		success := "true"
		if f.rejectUpdates {
			success = "false"
		}
		_, _ = w.Write([]byte(`{"data":{"issueUpdate":{"lastSyncId":1,"success":` + success + `}}}`))
	default:
		f.searches = append(f.searches, body.Variables)
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
	require.Equal(t, "team-1", fake.searches[0]["teamID"])
	require.Equal(t, "issue-1", fake.mutations[0]["issueID"])
	require.Equal(t, map[string]any{"stateId": "state-done"}, fake.mutations[0]["issueUpdateInput"])
}

func TestCloseIssueDoesNotHoldTheLockDuringTheStateLookup(t *testing.T) {
	fake := &fakeLinear{stateType: "unstarted", holdStates: make(chan struct{})}
	integration := newTestIntegration(t, fake)
	release := sync.OnceFunc(func() { close(fake.holdStates) })
	t.Cleanup(release)

	errs := make(chan error, 2)
	for range 2 {
		go func() { errs <- integration.CloseIssue(testEvent()) }()
	}

	require.Eventually(t, func() bool {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return fake.stateQuery == 2
	}, 2*time.Second, 10*time.Millisecond, "a second close waits on the first one's Linear request")
	release()

	require.NoError(t, <-errs)
	require.NoError(t, <-errs)
	require.Len(t, fake.mutations, 2)
	require.Equal(t, map[string]any{"stateId": "state-done"}, fake.mutations[1]["issueUpdateInput"])
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
	for _, stateType := range []string{"completed", "canceled", "duplicate"} {
		fake := &fakeLinear{stateType: stateType}
		integration := newTestIntegration(t, fake)

		require.NoError(t, integration.CloseIssue(testEvent()))
		require.Empty(t, fake.mutations, stateType)
	}
}

func TestCloseIssueFailsWhenLinearRejectsTheUpdate(t *testing.T) {
	fake := &fakeLinear{stateType: "started", rejectUpdates: true}
	integration := newTestIntegration(t, fake)

	require.ErrorContains(t, integration.CloseIssue(testEvent()), "Linear rejected the update")
}
