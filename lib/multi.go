package nuclei

import (
	"context"
	"time"

	"github.com/logrusorgru/aurora/v4"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/projectdiscovery/utils/errkit"
)

// unsafeOptions are those nuclei objects/instances/types
// that are required to run nuclei engine but are not thread safe
// hence they are ephemeral and are created on every ExecuteNucleiWithOpts invocation
// in ThreadSafeNucleiEngine
type unsafeOptions struct {
	executerOpts *protocols.ExecutorOptions
}

// createEphemeralObjects creates ephemeral nuclei objects/instances/types.
// outputWriter overrides the base engine writer when non-nil (used for per-call callbacks).
func createEphemeralObjects(ctx context.Context, base *NucleiEngine, opts *types.Options, outputWriter output.Writer) (*unsafeOptions, error) {
	if outputWriter == nil {
		outputWriter = base.customWriter
	}
	u := &unsafeOptions{}
	u.executerOpts = &protocols.ExecutorOptions{
		Output:       outputWriter,
		Options:      opts,
		Progress:     base.customProgress,
		Catalog:      base.catalog,
		IssuesClient: base.rc,
		RateLimiter:  base.rateLimiter,
		Interactsh:   base.interactshClient,
		Colorizer:    aurora.New(aurora.WithColors(true)),
		ResumeCfg:    types.NewResumeCfg(),
		Parser:       base.parser,
		Browser:      base.browserInstance,
		// Thread-safe executes can run concurrently with different Output writers.
		// The compiled-template cache shallow-copies requests and mutates shared
		// ExecutorOptions.Output via UpdateOptions/ApplyNewEngineOptions, which
		// would otherwise route all findings to whichever call last won the race.
		DoNotCache: true,
	}
	if opts.ShouldUseHostError() && base.hostErrCache != nil {
		u.executerOpts.HostErrorsCache = base.hostErrCache
	}
	if opts.RateLimitMinute > 0 {
		opts.RateLimit = opts.RateLimitMinute
		opts.RateLimitDuration = time.Minute
	}
	if opts.RateLimit > 0 && opts.RateLimitDuration == 0 {
		opts.RateLimitDuration = time.Second
	}
	u.executerOpts.RateLimiter = utils.GetRateLimiter(ctx, opts.RateLimit, opts.RateLimitDuration)
	return u, nil
}

// resolveEphemeralOutput combines the base/global writer with any per-call result callbacks.
// Global callbacks keep working; per-call callbacks are isolated to this execution.
func resolveEphemeralOutput(base, call *NucleiEngine) output.Writer {
	out := base.customWriter
	if call == nil || len(call.resultCallbacks) == 0 {
		return out
	}

	callbacks := append([]func(event *output.ResultEvent){}, call.resultCallbacks...)
	callWriter := testutils.NewMockOutputWriter(call.opts.OmitTemplate)
	callWriter.WriteCallback = func(event *output.ResultEvent) {
		for _, cb := range callbacks {
			if cb != nil {
				cb(event)
			}
		}
	}

	if out == nil {
		return callWriter
	}
	return output.NewMultiWriter(out, callWriter)
}

// closeEphemeralObjects closes all resources used by ephemeral nuclei objects/instances/types
func closeEphemeralObjects(u *unsafeOptions) {
	if u.executerOpts.RateLimiter != nil {
		u.executerOpts.RateLimiter.Stop()
	}
	// dereference all objects that were inherited from base nuclei engine
	// since these are meant to be closed globally by base nuclei engine
	u.executerOpts.Output = nil
	u.executerOpts.IssuesClient = nil
	u.executerOpts.Interactsh = nil
	u.executerOpts.HostErrorsCache = nil
	u.executerOpts.Progress = nil
	u.executerOpts.Catalog = nil
	u.executerOpts.Parser = nil
}

// ThreadSafeNucleiEngine is a tweaked version of nuclei.Engine whose methods are thread-safe
// and can be used concurrently. Non-thread-safe methods start with Global prefix
type ThreadSafeNucleiEngine struct {
	eng *NucleiEngine
}

// NewThreadSafeNucleiEngine creates a new nuclei engine with given options
// whose methods are thread-safe and can be used concurrently
// Note: Non-thread-safe methods start with Global prefix
func NewThreadSafeNucleiEngineCtx(ctx context.Context, opts ...NucleiSDKOptions) (*ThreadSafeNucleiEngine, error) {
	defaultOptions := types.DefaultOptions()
	e := &NucleiEngine{
		opts:   defaultOptions,
		mode:   threadSafe,
		ctx:    ctx,
		Logger: defaultOptions.Logger,
	}
	for _, option := range opts {
		if err := option(e); err != nil {
			return nil, err
		}
	}
	if err := e.init(ctx); err != nil {
		return nil, err
	}
	return &ThreadSafeNucleiEngine{eng: e}, nil
}

// Deprecated: use NewThreadSafeNucleiEngineCtx instead
func NewThreadSafeNucleiEngine(opts ...NucleiSDKOptions) (*ThreadSafeNucleiEngine, error) {
	return NewThreadSafeNucleiEngineCtx(context.Background(), opts...)
}

// GlobalLoadAllTemplates loads all templates from nuclei-templates repo
// This method will load all templates based on filters given at the time of nuclei engine creation in opts
func (e *ThreadSafeNucleiEngine) GlobalLoadAllTemplates() error {
	return e.eng.LoadAllTemplates()
}

// GlobalResultCallback sets a callback function which will be called for each result
// across all ExecuteNucleiWithOpts invocations. For a callback scoped to a single
// execution, pass WithResultCallback in that call's opts instead.
func (e *ThreadSafeNucleiEngine) GlobalResultCallback(callback func(event *output.ResultEvent)) {
	e.eng.resultCallbacks = []func(*output.ResultEvent){callback}
}

// ExecuteNucleiWithOptsCtx executes templates on targets and can be called concurrently.
// Pass WithResultCallback in opts for a per-execution result callback (combined with any
// GlobalResultCallback). Not all options are thread-safe.
func (e *ThreadSafeNucleiEngine) ExecuteNucleiWithOptsCtx(ctx context.Context, targets []string, opts ...NucleiSDKOptions) error {
	baseOpts := e.eng.opts.Copy()
	tmpEngine := &NucleiEngine{opts: baseOpts, mode: threadSafe}
	for _, option := range opts {
		if err := option(tmpEngine); err != nil {
			return err
		}
	}

	// create ephemeral nuclei objects/instances/types using base nuclei engine
	unsafeOpts, err := createEphemeralObjects(ctx, e.eng, tmpEngine.opts, resolveEphemeralOutput(e.eng, tmpEngine))
	if err != nil {
		return err
	}
	// cleanup and stop all resources
	defer closeEphemeralObjects(unsafeOpts)

	// load templates
	workflowLoader, err := workflow.NewLoader(unsafeOpts.executerOpts)
	if err != nil {
		return errkit.Wrapf(err, "Could not create workflow loader: %s", err)
	}
	unsafeOpts.executerOpts.WorkflowLoader = workflowLoader

	loaderConfig := loader.NewConfig(tmpEngine.opts, e.eng.catalog, unsafeOpts.executerOpts)
	loaderConfig.MetadataIndex = e.eng.getMetadataIndex()
	store, err := loader.New(loaderConfig)
	if err != nil {
		return errkit.Wrapf(err, "Could not create loader client: %s", err)
	}
	if err := store.Load(); err != nil {
		return errkit.Wrapf(err, "Could not load templates: %s", err)
	}

	inputProvider := provider.NewSimpleInputProviderWithUrls(e.eng.opts.ExecutionId, targets...)

	if len(store.Templates()) == 0 && len(store.Workflows()) == 0 {
		return ErrNoTemplatesAvailable
	}
	if inputProvider.Count() == 0 {
		return ErrNoTargetsAvailable
	}

	engine := core.New(tmpEngine.opts)
	engine.SetExecuterOptions(unsafeOpts.executerOpts)

	_ = engine.ExecuteScanWithOpts(ctx, store.Templates(), inputProvider, false)

	engine.WorkPool().Wait()
	return nil
}

// ExecuteNucleiWithOpts is same as ExecuteNucleiWithOptsCtx but with default context
// This is a placeholder and will be deprecated in future major release
func (e *ThreadSafeNucleiEngine) ExecuteNucleiWithOpts(targets []string, opts ...NucleiSDKOptions) error {
	return e.ExecuteNucleiWithOptsCtx(context.Background(), targets, opts...)
}

// Close all resources used by nuclei engine
func (e *ThreadSafeNucleiEngine) Close() {
	e.eng.Close()
}
