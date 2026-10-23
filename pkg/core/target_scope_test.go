package core

import (
	"context"
	"slices"
	"sync"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	tmpltypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types/scanstrategy"
	"github.com/stretchr/testify/require"
)

// allowList selects the templates it lists.
type allowList struct{ paths []string }

func (a *allowList) Allows(templatePath string) bool { return slices.Contains(a.paths, templatePath) }

// scopeByInput maps inputs to selections; unlisted inputs are unrestricted.
type scopeByInput map[string]*allowList

func (s scopeByInput) For(input *contextargs.MetaInput) protocols.TemplateSelection {
	if selection, ok := s[input.Input]; ok {
		return selection
	}
	return nil
}

// recordingExecuter records the inputs it runs on.
type recordingExecuter struct {
	path string
	mu   *sync.Mutex
	runs *[]string
}

func (r *recordingExecuter) Compile() error { return nil }
func (r *recordingExecuter) Requests() int  { return 1 }
func (r *recordingExecuter) Execute(ctx *scan.ScanContext) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	*r.runs = append(*r.runs, r.path+"@"+ctx.Input.MetaInput.Input)
	return false, nil
}
func (r *recordingExecuter) ExecuteWithResults(*scan.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

// progressRecorder captures the expected request count; the engine calls no
// other progress method on this path.
type progressRecorder struct {
	progress.Progress
	requests int64
}

func (p *progressRecorder) Init(_ int64, _ int, requests int64) { p.requests = requests }

func TestExecuteScanRunsOnlyScopedPairs(t *testing.T) {
	for _, strategy := range []scanstrategy.ScanStrategy{scanstrategy.TemplateSpray, scanstrategy.HostSpray} {
		t.Run(strategy.String(), func(t *testing.T) {
			options := &types.Options{
				BulkSize:                2,
				TemplateThreads:         2,
				HeadlessBulkSize:        1,
				HeadlessTemplateThreads: 1,
				ScanStrategy:            strategy.String(),
			}
			progress := &progressRecorder{}
			engine := New(options)
			engine.SetExecuterOptions(&protocols.ExecutorOptions{
				Logger:       engine.Logger,
				Options:      options,
				ResumeCfg:    types.NewResumeCfg(),
				ProtocolType: tmpltypes.HTTPProtocol,
				Progress:     progress,
				TargetScope: scopeByInput{
					"php":    {paths: []string{"thinkphp.yaml"}},
					"tomcat": {paths: []string{"tomcat.yaml", "generic.yaml"}},
					"none":   {},
				},
			})

			var (
				mu   sync.Mutex
				runs []string
			)
			var templatesList []*templates.Template
			for _, path := range []string{"thinkphp.yaml", "tomcat.yaml", "generic.yaml"} {
				templatesList = append(templatesList, &templates.Template{
					ID:            path,
					Path:          path,
					TotalRequests: 1,
					Executer:      &recordingExecuter{path: path, mu: &mu, runs: &runs},
				})
			}
			targets := &fakeTargetProvider{values: []*contextargs.MetaInput{
				{Input: "php"}, {Input: "tomcat"}, {Input: "none"}, {Input: "plain"},
			}}

			engine.ExecuteScanWithOpts(context.Background(), templatesList, targets, true)

			require.ElementsMatch(t, []string{
				"thinkphp.yaml@php",
				"tomcat.yaml@tomcat", "generic.yaml@tomcat",
				"thinkphp.yaml@plain", "tomcat.yaml@plain", "generic.yaml@plain",
			}, runs)
			require.EqualValues(t, len(runs), progress.requests, "progress counts only scoped pairs")
		})
	}
}
