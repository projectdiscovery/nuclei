package nuclei_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/require"
)

func TestContextCancelNucleiEngine(t *testing.T) {
	// create nuclei engine with options
	ctx, cancel := context.WithCancel(context.Background())
	ne, err := nuclei.NewNucleiEngineCtx(ctx,
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{Tags: []string{"oast"}}),
		nuclei.EnableStatsWithOpts(nuclei.StatsOptions{MetricServerPort: 0}),
	)
	require.NoError(t, err, "could not create nuclei engine")

	go func() {
		time.Sleep(time.Second * 2)
		cancel()
		log.Println("Test: context cancelled")
	}()

	// load targets and optionally probe non http/https targets
	ne.LoadTargets([]string{"http://honey.scanme.sh"}, false)
	// when callback is nil it nuclei will print JSON output to stdout
	err = ne.ExecuteWithCallback(nil)
	if err != nil {
		// we expect a context cancellation error
		require.ErrorIs(t, err, context.Canceled, "was expecting context cancellation error")
	}
	defer ne.Close()
}

func TestHeadlessOptionInitialization(t *testing.T) {
	ne, err := nuclei.NewNucleiEngineCtx(
		context.Background(),
		nuclei.EnableHeadlessWithOpts(&nuclei.HeadlessOpts{
			PageTimeout:     20,
			ShowBrowser:     false,
			UseChrome:       false,
			HeadlessOptions: []string{},
		}),
	)

	require.NoError(t, err, "could not create nuclei engine with headless options")
	require.NotNil(t, ne, "nuclei engine should not be nil")

	// Verify logger is initialized
	require.NotNil(t, ne.Logger, "logger should be initialized")

	defer ne.Close()
}

func TestMultiPartForm_ConcurrentMapWrites_SDK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer ts.Close()

	parsedURL, err := url.Parse(ts.URL)
	require.NoError(t, err)
	host := parsedURL.Host

	tmpTemplate, err := os.CreateTemp(t.TempDir(), "multipart-fuzz-*.yaml")
	require.NoError(t, err)
	_, err = tmpTemplate.WriteString(`id: multipart-fuzz

info:
  name: multipart form body fuzzing
  author: pdteam
  severity: info

http:
  - pre-condition:
      - type: dsl
        dsl:
          - method != "GET"
          - method != "HEAD"
          - contains(content_type, "multipart/form-data")
        condition: and

    payloads:
      injection:
        - "'"
        - "\""
        - ";"

    fuzzing:
      - part: body
        type: postfix
        mode: single
        fuzz:
          - '{{injection}}'

    stop-at-first-match: true
    matchers:
      - type: word
        words:
          - "ok"`)
	require.NoError(t, err)
	require.NoError(t, tmpTemplate.Close())

	tmpInput, err := os.CreateTemp(t.TempDir(), "input-proxify-*.yaml")
	require.NoError(t, err)

	for i := range 20 {
		_, err = fmt.Fprintf(tmpInput, `---
timestamp: 2024-01-01T00:00:00+00:00
url: %s/upload-%d
request:
  header:
    Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
    method: POST
    path: /upload-%d
    host: %s
  raw: |+
    POST /upload-%d HTTP/1.1
    Host: %s
    Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

    ------WebKitFormBoundary7MA4YWxkTrZu0gW
    Content-Disposition: form-data; name="file"; filename="test.txt"
    Content-Type: text/plain

    file content %d
    ------WebKitFormBoundary7MA4YWxkTrZu0gW
    Content-Disposition: form-data; name="description"

    test upload %d
    ------WebKitFormBoundary7MA4YWxkTrZu0gW--
response:
  header:
    Content-Type: text/plain
  raw: |+
    HTTP/1.1 200 OK
    Content-Type: text/plain

    ok
`, ts.URL, i, i, host, i, host, i, i)
		require.NoError(t, err)
	}
	require.NoError(t, tmpInput.Close())

	ne, err := nuclei.NewNucleiEngineCtx(
		context.Background(),
		nuclei.DASTMode(),
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: []string{tmpTemplate.Name()},
		}),
		nuclei.DisableUpdateCheck(),
	)
	require.NoError(t, err)
	defer ne.Close()

	err = ne.LoadTargetsWithHttpData(tmpInput.Name(), "yaml")
	require.NoError(t, err)

	err = ne.ExecuteCallbackWithCtx(context.Background(), func(event *output.ResultEvent) {
		t.Logf("Result: %s", event.TemplateID)
	})
	if err != nil {
		t.Errorf("ExecuteCallbackWithCtx error: %v", err)
	}
}
