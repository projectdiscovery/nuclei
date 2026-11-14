package runner

import (
	"context"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/targetprofile"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
)

// executeWithDetectedTech runs the tech templates first, then the rest with
// each target narrowed to the tech they detected on it, as a `tech` target
// line does: templates bound to an undetected product are skipped, every
// other template runs. A target nothing was detected on runs everything.
func (r *Runner) executeWithDetectedTech(executorOpts *protocols.ExecutorOptions, store *loader.Store, engine *core.Engine) (*atomic.Bool, error) {
	provider, ok := r.inputProvider.(interface {
		TargetProfiles() *targetprofile.Registry
	})
	if !ok {
		return nil, errors.New("-auto-tech needs a target list")
	}
	var fingerprints, rest []*templates.Template
	for _, template := range store.Templates() {
		if slices.Contains(template.Info.Tags.ToSlice(), "tech") {
			fingerprints = append(fingerprints, template)
		} else {
			rest = append(rest, template)
		}
	}
	rest = append(rest, store.Workflows()...)
	if len(fingerprints) == 0 {
		r.Logger.Warning().Msgf("-auto-tech skips nothing: no templates tagged tech are loaded")
		return r.executeTemplatesInput(store, engine)
	}

	// both runs report to one progress, started for every template
	if executorOpts.Progress != nil {
		scanProgress := executorOpts.Progress
		executorOpts.Progress = &sharedRunProgress{Progress: scanProgress, templates: len(fingerprints) + len(rest)}
		defer func() { executorOpts.Progress = scanProgress }()
	}

	detected := newDetectedTech()
	engine.SetResultHook(detected.add)
	// unclustered, as a cluster writes its results without passing them to the
	// hook; requests clustering would merge are identical, so the shared
	// responses still send each once
	results := engine.ExecuteScanWithOpts(context.Background(), fingerprints, r.inputProvider, true)
	engine.SetResultHook(nil)

	profiles := provider.TargetProfiles()
	for _, target := range detected.targets() {
		if err := profiles.BindTech(target.input, target.tech); err != nil {
			return nil, err
		}
	}
	r.Logger.Info().Msgf("Detected tech on %d targets, skipping templates bound to other products there", len(detected.byTarget))
	if len(rest) == 0 {
		return results, nil
	}
	profiles.Prepare(rest)
	executorOpts.TargetScope = profiles
	matched := engine.ExecuteScanWithOpts(context.Background(), rest, r.inputProvider, r.options.DisableClustering)
	results.CompareAndSwap(false, matched.Load())
	return results, nil
}

// detectedTech collects, per target, the names the tech templates matched:
// matcher names (tech-detect reports products that way), declared products,
// and template ids without -detect. Extra names only select more templates.
type detectedTech struct {
	mu       sync.Mutex
	byTarget map[detectedKey]*detectedTarget
}

type detectedKey struct {
	input string
	ip    string
}

type detectedTarget struct {
	input *contextargs.MetaInput
	tech  []string
}

func newDetectedTech() *detectedTech {
	return &detectedTech{byTarget: make(map[detectedKey]*detectedTarget)}
}

func (d *detectedTech) add(input *contextargs.MetaInput, results []*output.ResultEvent) {
	var tech []string
	for _, result := range results {
		if !result.MatcherStatus {
			continue
		}
		tech = append(tech, strings.TrimSuffix(result.TemplateID, "-detect"))
		if result.MatcherName != "" {
			tech = append(tech, result.MatcherName)
		}
		if product, ok := result.Info.Metadata["product"].(string); ok && product != "" {
			tech = append(tech, product)
		}
	}
	if len(tech) == 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	key := detectedKey{input: input.Input, ip: input.CustomIP}
	target, ok := d.byTarget[key]
	if !ok {
		target = &detectedTarget{input: input}
		d.byTarget[key] = target
	}
	target.tech = append(target.tech, tech...)
}

func (d *detectedTech) targets() []*detectedTarget {
	d.mu.Lock()
	defer d.mu.Unlock()
	targets := make([]*detectedTarget, 0, len(d.byTarget))
	for _, target := range d.byTarget {
		slices.Sort(target.tech)
		target.tech = slices.Compact(target.tech)
		targets = append(targets, target)
	}
	return targets
}

// sharedRunProgress is started by the first run with the templates of all
// runs; later runs add their requests to its total instead of starting over.
type sharedRunProgress struct {
	progress.Progress
	templates int
	started   bool
}

func (p *sharedRunProgress) Init(hostCount int64, rulesCount int, requestCount int64) {
	if p.started {
		p.AddToTotal(requestCount)
		return
	}
	p.started = true
	p.Progress.Init(hostCount, p.templates, requestCount)
}

func (p *sharedRunProgress) AddToTaskTotal(delta int64) {
	if tracker, ok := p.Progress.(progress.TaskTracker); ok {
		tracker.AddToTaskTotal(delta)
	}
}

func (p *sharedRunProgress) IncrementTasksBy(count int64) {
	if tracker, ok := p.Progress.(progress.TaskTracker); ok {
		tracker.IncrementTasksBy(count)
	}
}
