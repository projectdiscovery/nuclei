package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/projectfile"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/simplifiedchinese"
)

// A plain request under -project must decode a legacy charset once, both when
// the response comes from the server and when it is replayed from the cache.
func TestProjectCacheReplayDecodesCharsetOnce(t *testing.T) {
	cases := []struct {
		name    string
		charset string
		enc     encoding.Encoding
		text    string
	}{
		{name: "windows-1251", charset: "windows-1251", enc: charmap.Windows1251, text: "Привет, мир"},
		{name: "gbk", charset: "gbk", enc: simplifiedchinese.GBK, text: "你好，世界"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := tc.enc.NewEncoder().String(tc.text)
			require.NoError(t, err)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain; charset="+tc.charset)
				_, _ = w.Write([]byte(encoded))
			}))
			defer ts.Close()

			project, err := projectfile.New(&projectfile.Options{Path: t.TempDir(), Cleanup: true})
			require.NoError(t, err)
			defer project.Close()

			execute := func(t *testing.T) string {
				options := testutils.DefaultOptions
				testutils.Init(options)
				request := &Request{
					ID:   "project-charset",
					Path: []string{"{{BaseURL}}"},
					Operators: operators.Operators{Extractors: []*extractors.Extractor{{
						Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.DSLExtractor},
						DSL:  []string{"body"},
					}}},
				}
				executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
					ID:   "project-charset",
					Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Info}, Name: "test"},
				})
				executerOpts.ProjectFile = project
				require.NoError(t, request.Compile(executerOpts))

				var event output.InternalEvent
				err := request.ExecuteWithResults(contextargs.NewWithInput(context.Background(), ts.URL), output.InternalEvent{}, output.InternalEvent{}, func(e *output.InternalWrappedEvent) {
					event = e.InternalEvent
				})
				require.NoError(t, err)
				body, _ := event["body"].(string)
				return body
			}

			require.Equal(t, tc.text, execute(t), "first run decodes the response")
			require.Equal(t, tc.text, execute(t), "replayed run must not decode the body again")
		})
	}
}
