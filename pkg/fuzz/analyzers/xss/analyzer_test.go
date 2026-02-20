package xss

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/component"
	"github.com/projectdiscovery/retryablehttp-go"
)

func TestClassifyContexts(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		payload   string
		wantMatch bool
		wantIn    string
	}{
		{
			name:      "script context",
			body:      `<html><script>var x = "PAYLOAD";</script></html>`,
			payload:   "PAYLOAD",
			wantMatch: true,
			wantIn:    "script",
		},
		{
			name:      "attribute context",
			body:      `<img src="x" onerror="PAYLOAD">`,
			payload:   "PAYLOAD",
			wantMatch: true,
			wantIn:    "attribute",
		},
		{
			name:      "comment context",
			body:      `<!-- PAYLOAD -->`,
			payload:   "PAYLOAD",
			wantMatch: true,
			wantIn:    "comment",
		},
		{
			name:      "html context",
			body:      `<div>hello PAYLOAD world</div>`,
			payload:   "PAYLOAD",
			wantMatch: true,
			wantIn:    "html context",
		},
		{
			name:      "not reflected",
			body:      `<div>hello world</div>`,
			payload:   "PAYLOAD",
			wantMatch: false,
			wantIn:    "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matched, reason := classifyContexts(tc.body, tc.payload)
			if matched != tc.wantMatch {
				t.Fatalf("matched=%v want=%v reason=%q", matched, tc.wantMatch, reason)
			}
			if tc.wantIn != "" && reason != "" && !strings.Contains(reason, tc.wantIn) {
				t.Fatalf("reason=%q does not include %q", reason, tc.wantIn)
			}
		})
	}
}

func TestAnalyze_UsesFinalValueAndRestoresComponent(t *testing.T) {
	component := &fakeComponent{current: "seed"}
	analyzer := &Analyzer{}

	matched, reason, err := analyzer.Analyze(&analyzers.Options{
		FuzzGenerated: fuzz.GeneratedRequest{
			Component:       component,
			Key:             "k",
			Value:           "foo[RANDNUM]",
			OriginalPayload: "bar[RANDNUM]",
		},
		HttpClient: newTestClient(true),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Fatalf("expected reflection match, reason=%q", reason)
	}
	if len(component.setCalls) != 2 {
		t.Fatalf("expected 2 SetValue calls (set + restore), got %d", len(component.setCalls))
	}
	if !strings.HasPrefix(component.setCalls[0].value, "foo") {
		t.Fatalf("expected first SetValue to use transformed gr.Value, got %q", component.setCalls[0].value)
	}
	if component.setCalls[1].value != "foo[RANDNUM]" {
		t.Fatalf("expected restore SetValue to use original gr.Value, got %q", component.setCalls[1].value)
	}
	if component.rebuildCalls != 1 {
		t.Fatalf("expected Rebuild to be called once, got %d", component.rebuildCalls)
	}
}

func TestAnalyze_NoReflection(t *testing.T) {
	component := &fakeComponent{current: "seed"}
	analyzer := &Analyzer{}

	matched, reason, err := analyzer.Analyze(&analyzers.Options{
		FuzzGenerated: fuzz.GeneratedRequest{
			Component:       component,
			Key:             "k",
			Value:           "probe",
			OriginalPayload: "template",
		},
		HttpClient: newTestClient(false),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Fatalf("expected no reflection match, reason=%q", reason)
	}
	if len(component.setCalls) != 2 {
		t.Fatalf("expected 2 SetValue calls (set + restore), got %d", len(component.setCalls))
	}
}

func TestAnalyze_EmptyPayloadEarlyExit(t *testing.T) {
	component := &fakeComponent{current: "seed"}
	analyzer := &Analyzer{}

	matched, reason, err := analyzer.Analyze(&analyzers.Options{
		FuzzGenerated: fuzz.GeneratedRequest{
			Component:       component,
			Key:             "k",
			Value:           "",
			OriginalPayload: "ignored",
		},
		HttpClient: newTestClient(true),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched || reason != "" {
		t.Fatalf("expected empty early exit, got matched=%v reason=%q", matched, reason)
	}
	if len(component.setCalls) != 0 {
		t.Fatalf("expected no SetValue calls on empty payload, got %d", len(component.setCalls))
	}
	if component.rebuildCalls != 0 {
		t.Fatalf("expected no Rebuild calls on empty payload, got %d", component.rebuildCalls)
	}
}

type roundTripFn func(req *http.Request) (*http.Response, error)

func (f roundTripFn) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newTestClient(reflectPayload bool) *retryablehttp.Client {
	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	client.HTTPClient.Transport = roundTripFn(func(req *http.Request) (*http.Response, error) {
		body := "<html><body>no reflection</body></html>"
		if reflectPayload {
			payload := req.URL.Query().Get("k")
			body = "<html><body>" + payload + "</body></html>"
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	})
	return client
}

type setCall struct {
	key   string
	value string
}

type fakeComponent struct {
	key          string
	current      string
	setCalls     []setCall
	rebuildCalls int
}

func (f *fakeComponent) Name() string { return "fake" }

func (f *fakeComponent) Parse(_ *retryablehttp.Request) (bool, error) { return true, nil }

func (f *fakeComponent) Iterate(cb func(key string, value interface{}) error) error {
	if cb == nil {
		return nil
	}
	return cb(f.key, f.current)
}

func (f *fakeComponent) SetValue(key string, value string) error {
	f.key = key
	f.current = value
	f.setCalls = append(f.setCalls, setCall{key: key, value: value})
	return nil
}

func (f *fakeComponent) Delete(_ string) error { return nil }

func (f *fakeComponent) Rebuild() (*retryablehttp.Request, error) {
	f.rebuildCalls++
	query := url.Values{}
	query.Set(f.key, f.current)
	return retryablehttp.NewRequest(http.MethodGet, "https://example.test/?"+query.Encode(), nil)
}

func (f *fakeComponent) Clone() component.Component {
	copied := *f
	copied.setCalls = append([]setCall(nil), f.setCalls...)
	return &copied
}
