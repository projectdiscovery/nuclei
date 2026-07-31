package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

type testServer struct{ *Server }

func newTestServer() *testServer {
	cfg := &types.Options{}
	cfg.BulkSize = 10
	cfg.TemplateThreads = 5
	cfg.RateLimit = 50
	cfg.RateLimitDuration = 1 * time.Second
	cfg.PayloadConcurrency = 2
	cfg.ProbeConcurrency = 3
	cfg.JsConcurrency = 4
	return &testServer{Server: New("", cfg)}
}

func (ts *testServer) ServeHTTP(w http.ResponseWriter, r *http.Request) { ts.handleConcurrency(w, r) }

func TestUpdateSettings_RejectsNegativeValues(t *testing.T) {
	ts := newTestServer()
	reqBody := Concurrency{BulkSize: -1, Threads: -1, RateLimit: -5, PayloadConcurrency: -3, ProbeConcurrency: -2, JavascriptConcurrency: -7}
	buf, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPut, "/api/concurrency", bytes.NewReader(buf))
	rw := httptest.NewRecorder()
	ts.ServeHTTP(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for negative values, got %d", rw.Code)
	}
}

func TestUpdateSettings_DurationParsingAndBounds(t *testing.T) {
	ts := newTestServer()
	// invalid format
	buf, _ := json.Marshal(Concurrency{RateLimitDuration: "not-a-duration"})
	req := httptest.NewRequest(http.MethodPut, "/api/concurrency", bytes.NewReader(buf))
	rw := httptest.NewRecorder()
	ts.ServeHTTP(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid duration, got %d", rw.Code)
	}
	// negative duration
	buf, _ = json.Marshal(Concurrency{RateLimitDuration: "-1s"})
	req = httptest.NewRequest(http.MethodPut, "/api/concurrency", bytes.NewReader(buf))
	rw = httptest.NewRecorder()
	ts.ServeHTTP(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for negative duration, got %d", rw.Code)
	}
}

func TestUpdateSettings_ZeroValuesNoChange(t *testing.T) {
	ts := newTestServer()
	original := *ts.config
	buf, _ := json.Marshal(Concurrency{BulkSize: 0, Threads: 0, RateLimit: 0, PayloadConcurrency: 0, ProbeConcurrency: 0, JavascriptConcurrency: 0})
	req := httptest.NewRequest(http.MethodPut, "/api/concurrency", bytes.NewReader(buf))
	rw := httptest.NewRecorder()
	ts.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200 for zero values, got %d", rw.Code)
	}
	if original != *ts.config {
		t.Fatalf("expected no changes when sending zero values")
	}
}
