package nuclei_test

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
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

func TestThreadSafeNucleiEngineWithNoHostErrors(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nuclei-test-no-host-errors-*")
	require.NoError(t, err)

	tempTemplate, err := os.CreateTemp(tmpDir, "thread-safe-no-host-errors.*.yaml")
	require.NoError(t, err)

	_, err = tempTemplate.WriteString(`id: thread-safe-no-host-errors
info:
  name: Thread Safe (NoHostErrors)
  author: nuclei-sdk-test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "ok"`)
	require.NoError(t, err)
	require.NoError(t, tempTemplate.Close())

	options := types.DefaultOptions().Copy()
	options.NoHostErrors = true
	options.Timeout = 2
	options.Retries = 0
	options.BulkSize = 1
	options.TemplateThreads = 1
	options.Templates = append(options.Templates, tempTemplate.Name())

	ne, err := nuclei.NewThreadSafeNucleiEngineCtx(context.TODO(), nuclei.WithOptions(options))
	require.NoError(t, err, "could not create nuclei engine")

	defer func() {
		ne.Close()
		_ = os.RemoveAll(tmpDir)
	}()

	err = ne.GlobalLoadAllTemplates()
	require.NoError(t, err, "could not load templates")

	err = ne.ExecuteNucleiWithOptsCtx(context.TODO(), []string{"scanme.sh"})
	require.NoError(t, err, "nuclei execution should not return an error")
}

func TestWithOptionsRateLimitSetsRuntimeLimiter(t *testing.T) {
	opts := types.DefaultOptions().Copy()
	opts.RateLimit = 500
	opts.RateLimitDuration = time.Second

	ne, err := nuclei.NewNucleiEngineCtx(context.Background(), nuclei.WithOptions(opts))
	require.NoError(t, err, "could not create nuclei engine")
	t.Cleanup(func() {
		ne.Close()
	})

	execOpts := ne.GetExecuterOptions()
	require.NotNil(t, execOpts, "executor options should be initialized")
	require.NotNil(t, execOpts.RateLimiter, "rate limiter should be initialized")
	require.Equal(t, opts.RateLimit, int(execOpts.RateLimiter.GetLimit()), "runtime limiter should match rate limit from WithOptions")
}

// TestIgnoreFileFilesSectionIsApplied verifies the SDK applies BOTH sections of
// .nuclei-ignore, matching the CLI runner. The files section suppresses
// templates known to have weak matchers, so skipping it hands SDK consumers
// false positives the CLI would never report.
func TestIgnoreFileFilesSectionIsApplied(t *testing.T) {
	previousConfigDir := config.DefaultConfig.GetConfigDir()
	previousTemplatesDir := config.DefaultConfig.TemplatesDirectory
	previousStateDir := config.DefaultConfig.GetStateDir()
	t.Cleanup(func() {
		config.DefaultConfig.SetConfigDir(previousConfigDir)
		config.DefaultConfig.SetStateDir(previousStateDir)
		config.DefaultConfig.SetTemplatesDir(previousTemplatesDir)
	})

	dir := t.TempDir()
	config.DefaultConfig.SetConfigDir(dir)
	config.DefaultConfig.SetTemplatesDir(dir)

	ignoreFile := "tags:\n  - dos\nfiles:\n  - http/fuzzing/wordpress-themes-detect.yaml\n"
	require.NoError(t, os.WriteFile(config.DefaultConfig.GetActiveIgnoreFilePath(), []byte(ignoreFile), 0o600))

	ne, err := nuclei.NewNucleiEngineCtx(context.Background(),
		nuclei.WithOptions(types.DefaultOptions()),
		nuclei.DisableUpdateCheck(),
	)
	require.NoError(t, err, "could not create nuclei engine")
	defer ne.Close()

	require.Contains(t, ne.Options().ExcludeTags, "dos",
		"tags section should reach ExcludeTags")
	require.Contains(t, ne.Options().ExcludedTemplates, "http/fuzzing/wordpress-themes-detect.yaml",
		"files section should reach ExcludedTemplates")
}

func TestSDKCustomPortTemplateDoesNotPoisonBaseHost(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "server-ok")
	}))
	defer ts.Close()

	// Allocate and immediately close a TCP listener to obtain a guaranteed closed local port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedPort := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())

	tplDir := t.TempDir()
	closedPortTpl := fmt.Sprintf(`id: closed-port-parallel-probe
info:
  name: Closed Port Parallel Probe
  author: test
  severity: info
http:
  - method: GET
    path:
      - "http://{{Hostname}}:%d/probe?p={{val}}"
    threads: 2
    payloads:
      val:
        - "1"
        - "2"
    matchers:
      - type: word
        words:
          - "never-matches"
`, closedPort)
	healthyTpl := `id: healthy-base-target-match
info:
  name: Healthy Base Target Match
  author: test
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "server-ok"
`
	closedPortPath := filepath.Join(tplDir, "01-closed-port.yaml")
	healthyPath := filepath.Join(tplDir, "02-healthy.yaml")
	require.NoError(t, os.WriteFile(closedPortPath, []byte(closedPortTpl), 0o600))
	require.NoError(t, os.WriteFile(healthyPath, []byte(healthyTpl), 0o600))

	for run := 1; run <= 3; run++ {
		ne, err := nuclei.NewNucleiEngineCtx(
			context.Background(),
			nuclei.DisableUpdateCheck(),
			nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
				Templates: []string{closedPortPath, healthyPath},
			}),
			nuclei.WithConcurrency(nuclei.Concurrency{
				TemplateConcurrency:           1,
				HostConcurrency:               1,
				HeadlessHostConcurrency:       1,
				HeadlessTemplateConcurrency:   1,
				JavascriptTemplateConcurrency: 1,
				TemplatePayloadConcurrency:    2,
				ProbeConcurrency:              1,
			}),
		)
		require.NoError(t, err)
		ne.Options().RestrictLocalNetworkAccess = false
		ne.Options().Timeout = 2
		ne.Options().Retries = 0

		ne.LoadTargets([]string{ts.URL}, false)

		var (
			mu         sync.Mutex
			matched    []string
			violations []*output.ResultEvent
		)
		err = ne.ExecuteCallbackWithCtx(context.Background(), func(event *output.ResultEvent) {
			mu.Lock()
			defer mu.Unlock()
			if !event.MatcherStatus || event.Error != "" {
				violations = append(violations, event)
			}
			matched = append(matched, event.TemplateID)
		})
		ne.Close()

		require.NoError(t, err, "run %d failed", run)
		require.Empty(t, violations, "ExecuteCallbackWithCtx must not emit non-matching or skip events when MatcherStatus is false")
		require.Equal(t, []string{"healthy-base-target-match"}, matched, "run %d should consistently match healthy base target after custom-port failure", run)
	}
}

func TestSDKSkipEventsRespectMatcherStatus(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedAddr := ln.Addr().String()
	require.NoError(t, ln.Close())

	tplDir := t.TempDir()
	for i := 1; i <= 3; i++ {
		tpl := fmt.Sprintf(`id: unreachable-check-%d
info:
  name: Unreachable Check %d
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/path-%d"
    matchers:
      - type: word
        words:
          - "ok"
`, i, i, i)
		require.NoError(t, os.WriteFile(filepath.Join(tplDir, fmt.Sprintf("0%d-tpl.yaml", i)), []byte(tpl), 0o600))
	}

	runScan := func(matcherStatus bool) []*output.ResultEvent {
		ne, err := nuclei.NewNucleiEngineCtx(
			context.Background(),
			nuclei.DisableUpdateCheck(),
			nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
				Templates: []string{tplDir},
			}),
			nuclei.WithConcurrency(nuclei.Concurrency{
				TemplateConcurrency:           1,
				HostConcurrency:               1,
				HeadlessHostConcurrency:       1,
				HeadlessTemplateConcurrency:   1,
				JavascriptTemplateConcurrency: 1,
				TemplatePayloadConcurrency:    1,
				ProbeConcurrency:              1,
			}),
		)
		require.NoError(t, err)
		ne.Options().RestrictLocalNetworkAccess = false
		ne.Options().Timeout = 1
		ne.Options().Retries = 0
		ne.Options().MatcherStatus = matcherStatus

		ne.LoadTargets([]string{"http://" + closedAddr}, false)

		var (
			mu     sync.Mutex
			events []*output.ResultEvent
		)
		err = ne.ExecuteCallbackWithCtx(context.Background(), func(event *output.ResultEvent) {
			mu.Lock()
			defer mu.Unlock()
			events = append(events, event)
		})
		ne.Close()
		require.NoError(t, err)
		return events
	}

	require.Empty(t, runScan(false), "skip/error events must not be emitted when MatcherStatus is false")
	require.NotEmpty(t, runScan(true), "skip/error events should be emitted when MatcherStatus is true")
}

