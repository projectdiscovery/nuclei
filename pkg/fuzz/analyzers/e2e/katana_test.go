// This file proves the full crawl-to-fuzz bridge end to end: a katana JSONL
// crawl file is parsed by the real `katana` input format, fed through the real
// provider.NewInputProvider, and each discovered request (carrying method,
// cookies and JSON body that a bare URL list cannot express) is driven through
// the real fuzzing+analyzer pipeline against a genuinely vulnerable app. This is
// the realistic DAST flow: crawl output in, findings out — no Docker, no network.
package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestKatanaInputToFuzzPipeline_E2E(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)

	app := newDastApp()
	defer app.Close()

	// Simulate a katana -jsonl crawl of the vulnerable app: a GET with a query
	// param, a GET carrying a session cookie, and a POST with a JSON body. The
	// last two are impossible to express with a plain URL list.
	jsonl := fmt.Sprintf(
		`{"request":{"method":"GET","endpoint":"%s/sqli?q=seed"}}
{"request":{"method":"GET","endpoint":"%s/posts","headers":{"Cookie":"lang=en"}}}
{"request":{"method":"POST","endpoint":"%s/account","headers":{"Content-Type":"application/json"},"body":"{\"name\":\"john\"}"}}
`, app.URL, app.URL, app.URL)

	dir := t.TempDir()
	crawlFile := filepath.Join(dir, "katana.jsonl")
	require.NoError(t, os.WriteFile(crawlFile, []byte(jsonl), 0o644))

	// Build the real input provider in katana mode (separate options object so we
	// don't mutate the shared executer options used elsewhere in the package).
	provOpts := types.DefaultOptions()
	provOpts.InputFileMode = "katana"
	provOpts.TargetsFilePath = crawlFile
	provOpts.DAST = true

	p, err := provider.NewInputProvider(provider.InputOptions{Options: provOpts})
	require.NoError(t, err, "katana provider must construct")
	require.EqualValues(t, 3, p.Count(), "provider must yield all three crawled requests")

	// Collect the parsed requests, keyed by endpoint path, preserving ReqResp.
	metas := map[string]*contextargs.MetaInput{}
	p.Iterate(func(meta *contextargs.MetaInput) bool {
		require.NotNil(t, meta.ReqResp, "katana input must carry a full request/response object")
		require.NotNil(t, meta.ReqResp.Request, "request must be present")
		metas[meta.ReqResp.URL.Path] = meta.Clone()
		return false // false => continue iterating
	})
	require.Len(t, metas, 3)

	// Each crawled request is fuzzed in its native position and the analyzer must
	// detect the injection, with the dsl matcher turning it into a finding.
	cases := []struct {
		name     string
		path     string
		analyzer string
		part     string
		keys     []string
	}{
		{"crawled-query-sqli", "/sqli", "sqli_error", "query", []string{"q"}},
		{"crawled-cookie-sqli", "/posts", "sqli_error", "cookie", []string{"lang"}},
		{"crawled-body-sqli", "/account", "sqli_error", "body", []string{"name"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			meta, ok := metas[tc.path]
			require.True(t, ok, "crawl must contain a request for %s", tc.path)

			ctxArgs := contextargs.NewWithMetaInput(context.Background(), meta)
			res := runPipelineCtx(t, options, tc.analyzer, tc.part, tc.keys, ctxArgs)

			require.True(t, res.analyzerFlag, "analyzer must flag the crawled %s request", tc.path)
			require.True(t, res.matched, "the dsl matcher must produce a finding for crawled %s", tc.path)
			require.NotEmpty(t, res.analyzerDetails)
		})
	}
}
