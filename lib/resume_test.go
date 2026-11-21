package nuclei_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib" //nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
	"github.com/projectdiscovery/nuclei/v3/pkg/output" //nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
	"github.com/stretchr/testify/assert"               //nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
	"github.com/stretchr/testify/require"              //nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
)

const sdkResumeTemplate = `id: sdk-resume
info:
  name: SDK resume
  author: nuclei-sdk-test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
`

func writeSDKResumeTemplate(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sdk-resume.yaml")
	require.NoError(t, os.WriteFile(path, []byte(sdkResumeTemplate), 0o600))

	return path
}

// TestWithResumeFileSkipsCompletedTemplate covers the load half of #8237: a
// resume file that marks the template as completed must stop the SDK from
// sending its requests, as the CLI's -resume does.
func TestWithResumeFileSkipsCompletedTemplate(t *testing.T) { //nolint:paralleltest // shared DefaultConfig
	var hits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	t.Cleanup(srv.Close)

	resumeFile := filepath.Join(t.TempDir(), "completed.cfg")
	require.NoError(t, os.WriteFile(resumeFile,
		[]byte(`{"resumeFrom":{"sdk-resume":{"completed":true,"inFlight":{}}}}`), 0o600))

	template := writeSDKResumeTemplate(t)
	sources := nuclei.TemplateSources{Templates: []string{template}} //nolint:exhaustruct,exhaustruct_v5 // only Templates

	engine, err := nuclei.NewNucleiEngineCtx(context.Background(),
		nuclei.WithTemplatesOrWorkflows(sources),
		nuclei.WithResumeFile(resumeFile),
		nuclei.DisableUpdateCheck(),
	)
	require.NoError(t, err)
	t.Cleanup(engine.Close)

	engine.LoadTargets([]string{srv.URL}, false)

	var results atomic.Int32

	require.NoError(t, engine.ExecuteCallbackWithCtx(context.Background(), func(*output.ResultEvent) { results.Add(1) }))

	assert.Zero(t, hits.Load(), "a completed template must not reach the target")
	assert.Zero(t, results.Load(), "a completed template must not report results")
}

// TestWithResumeFileRejectsInvalidFile keeps a corrupt resume file from being
// ignored silently, as the CLI fails on it.
func TestWithResumeFileRejectsInvalidFile(t *testing.T) { //nolint:paralleltest // shared DefaultConfig
	resumeFile := filepath.Join(t.TempDir(), "invalid.cfg")
	require.NoError(t, os.WriteFile(resumeFile, []byte("not json"), 0o600))

	engine, err := nuclei.NewNucleiEngineCtx(context.Background(),
		nuclei.WithResumeFile(resumeFile),
		nuclei.DisableUpdateCheck(),
	)
	if engine != nil {
		engine.Close()
	}

	require.Error(t, err)
}

// startHoldingServer serves a target that holds its hold-th request open until
// the client gives up and answers every other request with 200. It signals
// arrived when the held request comes in.
func startHoldingServer(t *testing.T, hold int32) (string, <-chan struct{}, *atomic.Int32) {
	t.Helper()

	var hits atomic.Int32

	arrived := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		if hits.Add(1) == hold {
			close(arrived)
			<-req.Context().Done()
		}
	}))
	t.Cleanup(srv.Close)

	return srv.URL, arrived, &hits
}

// scanUntilCancelled scans target with the resume file and cancels the scan once
// arrived is closed.
func scanUntilCancelled(t *testing.T, resumeFile, target string, arrived <-chan struct{}) error {
	t.Helper()

	template := writeSDKResumeTemplate(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		select {
		case <-arrived:
			cancel()
		case <-time.After(30 * time.Second):
			cancel()
		}
	}()

	sources := nuclei.TemplateSources{Templates: []string{template}} //nolint:exhaustruct,exhaustruct_v5 // only Templates

	engine, err := nuclei.NewNucleiEngineCtx(ctx,
		nuclei.WithTemplatesOrWorkflows(sources),
		nuclei.WithResumeFile(resumeFile),
		nuclei.DisableUpdateCheck(),
	)
	require.NoError(t, err)
	t.Cleanup(engine.Close)

	engine.LoadTargets([]string{target}, false)

	err = engine.ExecuteCallbackWithCtx(ctx)
	if err != nil {
		return fmt.Errorf("execute scan: %w", err)
	}

	return nil
}

// TestWithResumeFileSavesCancelledScan covers the save half of #8237: a scan
// cancelled while its request is in flight must save the template as unfinished
// with that target in flight, and a scan resumed from the file must run it.
func TestWithResumeFileSavesCancelledScan(t *testing.T) { //nolint:paralleltest // shared DefaultConfig
	target, arrived, hits := startHoldingServer(t, 1)
	resumeFile := filepath.Join(t.TempDir(), "state", "saved.cfg")

	require.ErrorIs(t, scanUntilCancelled(t, resumeFile, target, arrived), context.Canceled)

	data, err := os.ReadFile(resumeFile) //nolint:gosec // the path is a test temp file
	require.NoError(t, err, "a cancelled scan must save its resume file")

	var saved struct {
		ResumeFrom map[string]struct {
			Completed bool                `json:"completed"`
			InFlight  map[string]struct{} `json:"inFlight"`
		} `json:"resumeFrom"`
	}

	require.NoError(t, json.Unmarshal(data, &saved))
	require.Contains(t, saved.ResumeFrom, "sdk-resume")
	assert.False(t, saved.ResumeFrom["sdk-resume"].Completed, "a cancelled template is not completed")
	assert.NotEmpty(t, saved.ResumeFrom["sdk-resume"].InFlight, "the cancelled target must stay in flight")

	template := writeSDKResumeTemplate(t)
	sources := nuclei.TemplateSources{Templates: []string{template}} //nolint:exhaustruct,exhaustruct_v5 // only Templates

	engine, err := nuclei.NewNucleiEngineCtx(context.Background(),
		nuclei.WithTemplatesOrWorkflows(sources),
		nuclei.WithResumeFile(resumeFile),
		nuclei.DisableUpdateCheck(),
	)
	require.NoError(t, err)
	t.Cleanup(engine.Close)

	engine.LoadTargets([]string{target}, false)

	var results atomic.Int32

	require.NoError(t, engine.ExecuteCallbackWithCtx(context.Background(), func(*output.ResultEvent) { results.Add(1) }))

	assert.Equal(t, int32(2), hits.Load(), "the resumed scan must send the cancelled request again")
	assert.Equal(t, int32(1), results.Load())
}

// TestWithResumeFileSavesOnlyTheCancelledCall covers an engine that runs a scan
// twice: the first call finishes its template and the second is cancelled in
// flight. The saved file must describe the second call alone, or resuming from
// it would skip the work that call did not finish.
func TestWithResumeFileSavesOnlyTheCancelledCall(t *testing.T) { //nolint:paralleltest // shared DefaultConfig
	target, arrived, hits := startHoldingServer(t, 2)
	resumeFile := filepath.Join(t.TempDir(), "saved.cfg")

	template := writeSDKResumeTemplate(t)
	sources := nuclei.TemplateSources{Templates: []string{template}} //nolint:exhaustruct,exhaustruct_v5 // only Templates

	engine, err := nuclei.NewNucleiEngineCtx(context.Background(),
		nuclei.WithTemplatesOrWorkflows(sources),
		nuclei.WithResumeFile(resumeFile),
		nuclei.DisableUpdateCheck(),
	)
	require.NoError(t, err)
	t.Cleanup(engine.Close)

	engine.LoadTargets([]string{target}, false)

	require.NoError(t, engine.ExecuteCallbackWithCtx(context.Background()))
	require.Equal(t, int32(1), hits.Load(), "the first call must finish its request")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		select {
		case <-arrived:
			cancel()
		case <-time.After(30 * time.Second):
			cancel()
		}
	}()

	require.ErrorIs(t, engine.ExecuteCallbackWithCtx(ctx), context.Canceled)

	resumed, err := nuclei.NewNucleiEngineCtx(context.Background(),
		nuclei.WithTemplatesOrWorkflows(sources),
		nuclei.WithResumeFile(resumeFile),
		nuclei.DisableUpdateCheck(),
	)
	require.NoError(t, err)
	t.Cleanup(resumed.Close)

	resumed.LoadTargets([]string{target}, false)

	var results atomic.Int32

	require.NoError(t, resumed.ExecuteCallbackWithCtx(context.Background(), func(*output.ResultEvent) { results.Add(1) }))

	assert.Equal(t, int32(3), hits.Load(), "the resumed scan must send the request the second call did not finish")
	assert.Equal(t, int32(1), results.Load())
}

// TestWithResumeFileReportsFailedSave keeps a cancelled scan from hiding that
// its resume file was not written.
func TestWithResumeFileReportsFailedSave(t *testing.T) { //nolint:paralleltest // shared DefaultConfig
	// The parent of the resume file is a regular file, so saving cannot create it.
	blocker := filepath.Join(t.TempDir(), "blocker")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))

	target, arrived, _ := startHoldingServer(t, 1)
	err := scanUntilCancelled(t, filepath.Join(blocker, "saved.cfg"), target, arrived)

	require.ErrorIs(t, err, context.Canceled)
	require.ErrorContains(t, err, "resume", "the save failure must be reported")
}

// TestThreadSafeEngineIgnoresMalformedResumeFile holds the documented contract
// that the thread-safe engine ignores the resume file, so it does not even
// parse it.
func TestThreadSafeEngineIgnoresMalformedResumeFile(t *testing.T) { //nolint:paralleltest // shared DefaultConfig
	resumeFile := filepath.Join(t.TempDir(), "invalid.cfg")
	require.NoError(t, os.WriteFile(resumeFile, []byte("not json"), 0o600))

	engine, err := nuclei.NewThreadSafeNucleiEngineCtx(context.Background(),
		nuclei.WithResumeFile(resumeFile),
		nuclei.DisableUpdateCheck(),
	)
	require.NoError(t, err)
	engine.Close()
}
