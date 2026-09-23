package nuclei

import (
	"context"
	"os"
	"path/filepath"
	"testing"

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
