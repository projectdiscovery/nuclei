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
		name        string
		body        string
		payload     string
		wantMatch   bool
		wantContext string
	}{
		{
			name:        "script context",
			body:        `<html><script>const x = "PAYLOAD";</script></html>`,
			payload:     "PAYLOAD",
			wantMatch:   true,
			wantContext: contextScript,
		},
		{
			name:        "attribute context",
			body:        `<img src="x" onerror="PAYLOAD">`,
			payload:     "PAYLOAD",
			wantMatch:   true,
			wantContext: contextAttribute,
		},
		{
			name:        "comment context",
			body:        `<!-- PAYLOAD -->`,
			payload:     "PAYLOAD",
			wantMatch:   true,
			wantContext: contextComment,
		},
		{
			name:        "html context",
			body:        `<div>hello PAYLOAD world</div>`,
			payload:     "PAYLOAD",
			wantMatch:   true,
			wantContext: contextHTML,
		},
		{
			name:        "raw html fallback for malformed markup",
			body:        `<div attr=PAYLOAD`,
			payload:     "PAYLOAD",
			wantMatch:   true,
			wantContext: contextRawHTML,
		},
		{
			name:      "not reflected",
			body:      `<div>hello world</div>`,
			payload:   "PAYLOAD",
			wantMatch: false,
		},
		{
			name:      "empty payload",
			body:      `<div>PAYLOAD</div>`,
			payload:   "",
			wantMatch: false,
		},
		{
			name:      "empty body",
			body:      "",
			payload:   "PAYLOAD",
			wantMatch: false,
		},
		{
			name:        "multiple contexts chooses highest severity",
			body:        `<div>PAYLOAD</div><script>var s = "PAYLOAD"</script>`,
			payload:     "PAYLOAD",
			wantMatch:   true,
			wantContext: contextScript,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matched, reason := classifyContexts(tc.body, tc.payload)
			if matched != tc.wantMatch {
				t.Fatalf("matched=%v want=%v reason=%q", matched, tc.wantMatch, reason)
			}
			if tc.wantContext != "" {
				if !strings.Contains(reason, tc.wantContext) {
					t.Fatalf("reason=%q does not include context=%q", reason, tc.wantContext)
				}
			}
		})
	}
}

func TestAnalyzeUsesFinalValueAndRestoresComponent(t *testing.T) {
	fakeComp := &fakeComponent{current: "seed"}
	analyzer := &Analyzer{}

	matched, reason, err := analyzer.Analyze(&analyzers.Options{
		FuzzGenerated: fuzz.GeneratedRequest{
			Component:       fakeComp,
			Key:             "k",
			Value:           "final-payload",
			OriginalValue:   "seed",
			OriginalPayload: "template-[RANDSTR]",
		},
		HttpClient: newTestClient(true, "k"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched {
		t.Fatalf("expected reflection match, reason=%q", reason)
	}
	if len(fakeComp.setCalls) != 2 {
		t.Fatalf("expected 2 SetValue calls (set + restore), got %d", len(fakeComp.setCalls))
	}
	if fakeComp.setCalls[0].value != "final-payload" {
		t.Fatalf("expected first SetValue to use generated final value, got %q", fakeComp.setCalls[0].value)
	}
	if fakeComp.setCalls[1].value != "seed" {
		t.Fatalf("expected restore to use original value, got %q", fakeComp.setCalls[1].value)
	}
	if fakeComp.rebuildCalls != 1 {
		t.Fatalf("expected Rebuild to be called once, got %d", fakeComp.rebuildCalls)
	}
}

func TestAnalyzeNoReflection(t *testing.T) {
	fakeComp := &fakeComponent{current: "seed"}
	analyzer := &Analyzer{}

	matched, reason, err := analyzer.Analyze(&analyzers.Options{
		FuzzGenerated: fuzz.GeneratedRequest{
			Component:       fakeComp,
			Key:             "k",
			Value:           "probe",
			OriginalValue:   "seed",
			OriginalPayload: "template",
		},
		HttpClient: newTestClient(false, "k"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched || reason != "" {
		t.Fatalf("expected no reflection, got matched=%v reason=%q", matched, reason)
	}
	if len(fakeComp.setCalls) != 2 {
		t.Fatalf("expected 2 SetValue calls (set + restore), got %d", len(fakeComp.setCalls))
	}
	if fakeComp.setCalls[1].value != "seed" {
		t.Fatalf("expected restore to use original value, got %q", fakeComp.setCalls[1].value)
	}
}

func TestAnalyzeEmptyPayloadEarlyExit(t *testing.T) {
	fakeComp := &fakeComponent{current: "seed"}
	analyzer := &Analyzer{}

	matched, reason, err := analyzer.Analyze(&analyzers.Options{
		FuzzGenerated: fuzz.GeneratedRequest{
			Component:       fakeComp,
			Key:             "k",
			Value:           "",
			OriginalPayload: "template",
		},
		HttpClient: newTestClient(true, "k"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched || reason != "" {
		t.Fatalf("expected no match for empty payload, got matched=%v reason=%q", matched, reason)
	}
	if len(fakeComp.setCalls) != 0 {
		t.Fatalf("expected no SetValue calls for empty payload, got %d", len(fakeComp.setCalls))
	}
	if fakeComp.rebuildCalls != 0 {
		t.Fatalf("expected no Rebuild calls for empty payload, got %d", fakeComp.rebuildCalls)
	}
}

func TestAnalyzeApplyInitialTransformation(t *testing.T) {
	analyzer := &Analyzer{}
	transformed := analyzer.ApplyInitialTransformation("x-[RANDNUM]-[RANDSTR]", nil)
	if !strings.HasPrefix(transformed, "x-") {
		t.Fatalf("unexpected transformed payload prefix: %q", transformed)
	}
	if strings.Contains(transformed, "[RANDNUM]") || strings.Contains(transformed, "[RANDSTR]") {
		t.Fatalf("expected placeholder replacement, got %q", transformed)
	}
}

type roundTripFn func(req *http.Request) (*http.Response, error)

func (f roundTripFn) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newTestClient(reflectPayload bool, reflectKey string) *retryablehttp.Client {
	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	client.HTTPClient.Transport = roundTripFn(func(req *http.Request) (*http.Response, error) {
		body := "<html><body>no reflection</body></html>"
		if reflectPayload {
			payload := req.URL.Query().Get(reflectKey)
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
