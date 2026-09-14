package nuclei

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestCallerParserUsesEngineLocalCompiledCache(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "template.yaml")
	require.NoError(t, os.WriteFile(templatePath, []byte(`id: parser-lifecycle

info:
  name: Parser lifecycle
  author: pdteam
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}"
`), 0o600))

	callerParser := templates.NewParser()
	callerParser.Cache().StoreWithoutRaw("sentinel", &templates.Template{}, nil)

	for range 3 {
		compiledParser := func() *templates.Parser {
			opts := types.DefaultOptions()
			opts.Parser = callerParser
			opts.Templates = []string{templatePath}

			engine, err := NewNucleiEngineCtx(context.Background(), DisableUpdateCheck(), WithOptions(opts))
			require.NoError(t, err)

			engineParser := engine.GetParser()
			require.Same(t, callerParser, engineParser)
			require.False(t, engine.GetExecuterOptions().DoNotCache)

			compiledParser, ok := engine.GetExecuterOptions().Parser.(*templates.Parser)
			require.True(t, ok)
			require.NotSame(t, callerParser, compiledParser)
			require.Same(t, callerParser.Cache(), compiledParser.Cache())

			require.NoError(t, engine.LoadAllTemplates())
			require.Len(t, engine.GetTemplates(), 1)
			require.Equal(t, 0, callerParser.CompiledCount())
			require.Equal(t, 1, compiledParser.CompiledCount())
			require.Equal(t, 2, callerParser.ParsedCount())
			require.NoError(t, engine.LoadAllTemplates())
			require.Len(t, engine.GetTemplates(), 1)
			require.Equal(t, 1, compiledParser.CompiledCount())

			engine.Close()
			return compiledParser
		}()

		require.Equal(t, 0, callerParser.CompiledCount())
		require.Equal(t, 0, compiledParser.CompiledCount())
		require.Equal(t, 2, callerParser.ParsedCount())
		cached, err := callerParser.Cache().Get("sentinel")
		require.NoError(t, err)
		require.NotNil(t, cached)
	}
}

func TestThreadSafeExecuteUsesSharedCompiledCache(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "template.yaml")
	require.NoError(t, os.WriteFile(templatePath, []byte(`id: thread-safe-shared-cache

info:
  name: Thread safe shared cache
  author: pdteam
  severity: info
  tags: thread-safe-shared-cache

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "thread-safe-shared-cache"
`), 0o600))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("thread-safe-shared-cache"))
	}))
	t.Cleanup(server.Close)

	engine, err := NewThreadSafeNucleiEngineCtx(context.Background())
	require.NoError(t, err)
	t.Cleanup(engine.Close)

	const executions = 4
	var waitGroup sync.WaitGroup
	errors := make([]error, executions)
	for i := range executions {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			errors[i] = engine.ExecuteNucleiWithOptsCtx(context.Background(), []string{server.URL},
				WithTemplatesOrWorkflows(TemplateSources{Templates: []string{templatePath}}),
				WithTemplateFilters(TemplateFilters{Tags: []string{"thread-safe-shared-cache"}}),
				WithResultCallback(func(*output.ResultEvent) {}),
			)
		}()
	}
	waitGroup.Wait()

	for _, err := range errors {
		require.NoError(t, err)
	}
	require.Equal(t, 1, engine.eng.GetParser().CompiledCount())
}

func TestThreadSafeExecuteHonorsDisableTemplateCache(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "template.yaml")
	require.NoError(t, os.WriteFile(templatePath, []byte(`id: thread-safe-disable-cache

info:
  name: Thread safe disable cache
  author: pdteam
  severity: info
  tags: thread-safe-disable-cache

http:
  - method: GET
    path:
      - "{{BaseURL}}"
`), 0o600))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(server.Close)

	engine, err := NewThreadSafeNucleiEngineCtx(context.Background(), DisableTemplateCache())
	require.NoError(t, err)
	t.Cleanup(engine.Close)

	err = engine.ExecuteNucleiWithOptsCtx(context.Background(), []string{server.URL},
		WithTemplatesOrWorkflows(TemplateSources{Templates: []string{templatePath}}),
		WithTemplateFilters(TemplateFilters{Tags: []string{"thread-safe-disable-cache"}}),
	)
	require.NoError(t, err)
	require.Equal(t, 0, engine.eng.GetParser().CompiledCount())
}
