package core //nolint:testpackage // it uses the unexported test helpers of the package

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types/scanstrategy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const resumeTemplateID = "todo.yaml"

// holdExecuter blocks on the hold input until release is closed.
type holdExecuter struct {
	hold    string
	held    chan struct{}
	release chan struct{}
}

func (h *holdExecuter) Compile() error { return nil }
func (h *holdExecuter) Requests() int  { return 1 }
func (h *holdExecuter) Execute(ctx *scan.ScanContext) (bool, error) {
	if ctx.Input.MetaInput.Input == h.hold {
		close(h.held)
		<-h.release
	}

	return false, nil
}
func (h *holdExecuter) ExecuteWithResults(*scan.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

func resumeTemplate(executer protocols.Executer) *templates.Template {
	//nolint:exhaustruct,exhaustruct_v5 // zero values are the defaults
	// The template is http-only, as the engine checks the host of only those
	// before it runs them.
	return &templates.Template{
		ID: resumeTemplateID, Path: resumeTemplateID, TotalRequests: 1, Executer: executer,
		RequestsHTTP: []*http.Request{{}},
	}
}

// interruptedScan starts a template-spray scan of inputs that holds on the
// hold input, with the down inputs unresponsive. It returns the progress
// saved once hold is the only target in flight, and the positions in flight
// at that point.
func interruptedScan(
	t *testing.T, inputs, down []string, hold string, wantInFlight uint32,
) (*types.ResumeCfg, []uint32) {
	t.Helper()

	cfg := types.NewResumeCfg()
	engine, _ := newTaskEngine(scanstrategy.TemplateSpray, nil, downSet(down), cfg)
	executer := &holdExecuter{hold: hold, held: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(executer.release) })
	t.Cleanup(release)

	done := make(chan struct{})

	go func() {
		defer close(done)

		tpls := []*templates.Template{resumeTemplate(executer)}

		engine.ExecuteScanWithOpts(context.Background(), tpls, targetsOf(inputs...), true)
	}()

	select {
	case <-executer.held:
	case <-time.After(10 * time.Second):
		t.Fatalf("the scan never reached %s", hold)
	}

	var (
		saved *types.ResumeCfg
		got   []uint32
	)

	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		saved = cfg.Clone()
		got = slices.Sorted(maps.Keys(saved.Current[resumeTemplateID].InFlight))

		if slices.Equal(got, []uint32{wantInFlight}) {
			break
		}
	}

	release()
	<-done

	return saved, got
}

// downSet returns the set of unresponsive inputs.
func downSet(down []string) map[string]bool {
	set := make(map[string]bool, len(down))

	for _, input := range down {
		set[input] = true
	}

	return set
}

// resumeFromSaved saves and loads the progress as the -resume file does.
func resumeFromSaved(t *testing.T, saved *types.ResumeCfg) *types.ResumeCfg {
	t.Helper()

	data, err := json.Marshal(saved.Snapshot())
	require.NoError(t, err)

	cfg := types.NewResumeCfg()
	require.NoError(t, json.Unmarshal(data, cfg))
	cfg.Compile()

	return cfg
}

// resumedRuns returns the inputs a scan resumed from cfg runs the template on,
// with the down inputs unresponsive. A template that ran on a host before the
// interruption doesn't probe it again, so down lists the hosts that other
// templates found unresponsive during the resumed scan.
func resumedRuns(cfg *types.ResumeCfg, inputs, down []string) []string {
	var (
		mu   sync.Mutex
		runs []string
	)

	engine, _ := newTaskEngine(scanstrategy.TemplateSpray, nil, downSet(down), cfg)
	executer := &recordingExecuter{path: resumeTemplateID, mu: &mu, runs: &runs}
	tpls := []*templates.Template{resumeTemplate(executer)}
	engine.ExecuteScanWithOpts(context.Background(), tpls, targetsOf(inputs...), true)

	ran := make([]string, 0, len(runs))

	for _, run := range runs {
		ran = append(ran, strings.TrimPrefix(run, resumeTemplateID+"@"))
	}

	return ran
}

// resumeCase is a first scan of the space-separated inputs, interrupted while
// it ran the "c" input at position at. The first scan finds the down inputs
// unresponsive, and the resumed scan finds the resumedDown ones.
type resumeCase struct {
	name        string
	inputs      string
	down        string
	resumedDown string
	at          uint32
}

func resumeCases() []resumeCase {
	return []resumeCase{
		{name: "no-down-host", inputs: "a b c e", down: "", resumedDown: "", at: 2},
		{name: "first", inputs: "d a c e", down: "d", resumedDown: "", at: 2},
		{name: "middle", inputs: "a d c e", down: "d", resumedDown: "", at: 2},
		{name: "last", inputs: "a c d", down: "d", resumedDown: "", at: 1},
		{name: "consecutive", inputs: "a d1 d2 d3 c e", down: "d1 d2 d3", resumedDown: "", at: 4},
		{name: "scattered", inputs: "d1 a d2 c d3 e", down: "d1 d2 d3", resumedDown: "", at: 3},
		{name: "in-both-scans", inputs: "b d c f", down: "d", resumedDown: "d", at: 2},
		{name: "in-resumed-scan", inputs: "x d c y", down: "", resumedDown: "d", at: 2},
	}
}

// A resumed scan runs the interrupted target and everything after it, and
// nothing before it, wherever the unresponsive hosts of the first scan sat.
//
//nolint:paralleltest // each scan resets the shared HTTP responses of the process
func TestResumeAfterUnresponsiveHost(t *testing.T) {
	for _, test := range resumeCases() {
		t.Run(test.name, func(t *testing.T) {
			inputs := strings.Fields(test.inputs)
			resumedDown := strings.Fields(test.resumedDown)
			saved, inFlight := interruptedScan(t, inputs, strings.Fields(test.down), "c", test.at)
			assert.Equal(t, []uint32{test.at}, inFlight, "in-flight positions")

			// the interrupted target and the ones after it, but for the unresponsive
			want := slices.DeleteFunc(slices.Clone(inputs[test.at:]), func(input string) bool {
				return slices.Contains(resumedDown, input)
			})
			resumed := resumedRuns(resumeFromSaved(t, saved), inputs, resumedDown)
			assert.ElementsMatch(t, want, resumed, "targets of the resumed scan")
		})
	}
}
