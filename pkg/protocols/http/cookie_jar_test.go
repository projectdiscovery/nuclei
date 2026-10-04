package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/component"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestCookieJarDeduplicationOnSetCookie(t *testing.T) {
	var mu sync.Mutex
	var receivedCookies []string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cookieHeader := r.Header.Get("Cookie")
		receivedCookies = append(receivedCookies, cookieHeader)
		mu.Unlock()

		if strings.Contains(cookieHeader, "initial_token") {
			// Reissue session cookie on malformed or initial token
			http.SetCookie(w, &http.Cookie{
				Name:  "session",
				Value: "reissued_token",
				Path:  "/",
			})
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	options := testutils.DefaultOptions
	testutils.Init(options)

	templateID := "cookie-test"
	req := &Request{
		ID: templateID,
		Raw: []string{
			`GET / HTTP/1.1
Host: {{Hostname}}
Cookie: session=initial_token
`,
			`GET / HTTP/1.1
Host: {{Hostname}}
Cookie: session=initial_token
`,
		},
	}

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	require.NoError(t, req.Compile(executerOpts))

	metadata := make(output.InternalEvent)
	previous := make(output.InternalEvent)
	ctxArgs := contextargs.NewWithInput(context.Background(), ts.URL)
	err := req.ExecuteWithResults(ctxArgs, metadata, previous, func(event *output.InternalWrappedEvent) {})
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, receivedCookies, 2)
	t.Logf("Request 1 received Cookie: %s", receivedCookies[0])
	t.Logf("Request 2 received Cookie: %s", receivedCookies[1])

	// Request 2 must NOT have duplicate session cookies
	sessionCount := strings.Count(receivedCookies[1], "session=")
	require.Equal(t, 1, sessionCount, "Request 2 should have exactly one session cookie, got: %s", receivedCookies[1])
	require.Contains(t, receivedCookies[1], "session=reissued_token")
	require.NotContains(t, receivedCookies[1], "session=initial_token")
}

func TestCookieJarDeduplicationPreservesOtherCookies(t *testing.T) {
	var mu sync.Mutex
	var receivedCookies []string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cookieHeader := r.Header.Get("Cookie")
		receivedCookies = append(receivedCookies, cookieHeader)
		mu.Unlock()

		if strings.Contains(cookieHeader, "initial_token") {
			http.SetCookie(w, &http.Cookie{
				Name:  "session",
				Value: "reissued_token",
				Path:  "/",
			})
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	options := testutils.DefaultOptions
	testutils.Init(options)

	templateID := "cookie-preserve-test"
	req := &Request{
		ID: templateID,
		Raw: []string{
			`GET / HTTP/1.1
Host: {{Hostname}}
Cookie: lang=en; session=initial_token; theme=dark
`,
			`GET / HTTP/1.1
Host: {{Hostname}}
Cookie: lang=en; session=initial_token; theme=dark
`,
		},
	}

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	require.NoError(t, req.Compile(executerOpts))

	metadata := make(output.InternalEvent)
	previous := make(output.InternalEvent)
	ctxArgs := contextargs.NewWithInput(context.Background(), ts.URL)
	err := req.ExecuteWithResults(ctxArgs, metadata, previous, func(event *output.InternalWrappedEvent) {})
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, receivedCookies, 2)
	t.Logf("Request 2 received Cookie: %s", receivedCookies[1])

	// Must have exactly one session cookie, and preserved lang and theme
	require.Equal(t, 1, strings.Count(receivedCookies[1], "session="))
	require.Contains(t, receivedCookies[1], "session=reissued_token")
	require.NotContains(t, receivedCookies[1], "session=initial_token")
	require.Contains(t, receivedCookies[1], "lang=en")
	require.Contains(t, receivedCookies[1], "theme=dark")
}

func TestCookieJarDeduplicationPreservesIntentionalDuplicates(t *testing.T) {
	var mu sync.Mutex
	var receivedCookies []string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cookieHeader := r.Header.Get("Cookie")
		receivedCookies = append(receivedCookies, cookieHeader)
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	options := testutils.DefaultOptions
	testutils.Init(options)

	templateID := "cookie-hpp-test"
	req := &Request{
		ID: templateID,
		Raw: []string{
			`GET / HTTP/1.1
Host: {{Hostname}}
Cookie: hpp_param=value1; hpp_param=value2
`,
		},
	}

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	require.NoError(t, req.Compile(executerOpts))

	metadata := make(output.InternalEvent)
	previous := make(output.InternalEvent)
	ctxArgs := contextargs.NewWithInput(context.Background(), ts.URL)
	err := req.ExecuteWithResults(ctxArgs, metadata, previous, func(event *output.InternalWrappedEvent) {})
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, receivedCookies, 1)
	t.Logf("Request received Cookie: %s", receivedCookies[0])

	// Intentional duplicates NOT tracked in cookie jar must be preserved
	require.Equal(t, 2, strings.Count(receivedCookies[0], "hpp_param="))
	require.Contains(t, receivedCookies[0], "hpp_param=value1")
	require.Contains(t, receivedCookies[0], "hpp_param=value2")
}

func TestCookieJarDeduplicationWithFuzzedCookie(t *testing.T) {
	var mu sync.Mutex
	var receivedCookies []string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cookieHeader := r.Header.Get("Cookie")
		receivedCookies = append(receivedCookies, cookieHeader)
		mu.Unlock()

		if strings.Contains(cookieHeader, "initial_token") {
			http.SetCookie(w, &http.Cookie{
				Name:  "session",
				Value: "reissued_token",
				Path:  "/",
			})
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	options := testutils.DefaultOptions
	testutils.Init(options)

	templateID := "cookie-fuzz-test"
	req := &Request{
		ID: templateID,
		Raw: []string{
			`GET / HTTP/1.1
Host: {{Hostname}}
Cookie: session=initial_token
`,
			`GET / HTTP/1.1
Host: {{Hostname}}
Cookie: session=fuzzed_payload'
`,
		},
	}

	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	require.NoError(t, req.Compile(executerOpts))

	metadata := make(output.InternalEvent)
	previous := make(output.InternalEvent)
	ctxArgs := contextargs.NewWithInput(context.Background(), ts.URL)

	// Execute request 1 to populate jar with reissued_token
	err := req.ExecuteWithResults(ctxArgs, metadata, previous, func(event *output.InternalWrappedEvent) {})
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, receivedCookies, 2)
	t.Logf("Request 1 received Cookie: %s", receivedCookies[0])
	t.Logf("Request 2 received Cookie: %s", receivedCookies[1])

	// In request 2, session was not flagged as fuzzed in the raw template execution,
	// so it received the jar's reissued_token.
	require.Equal(t, 1, strings.Count(receivedCookies[1], "session="))
	require.Contains(t, receivedCookies[1], "session=reissued_token")
}

func TestCookieComponent_RebuildSpecialCharacters(t *testing.T) {
	c := component.NewCookie()
	baseReq, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)
	baseReq.Header.Set("Cookie", "session=e89fd5791dffd0524eb7a578df58be37")

	parsed, err := c.Parse(baseReq)
	require.NoError(t, err)
	require.True(t, parsed)

	// Set fuzz value containing quotes and verify it is not stripped
	err = c.SetValue("session", "e89fd5791dffd0524eb7a578df58be37\"")
	require.NoError(t, err)

	rebuilt, err := c.Rebuild()
	require.NoError(t, err)
	require.Equal(t, "session=e89fd5791dffd0524eb7a578df58be37\"", rebuilt.Header.Get("Cookie"))
}
