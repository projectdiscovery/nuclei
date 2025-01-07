package nuclei

import (
	"context"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/ratelimit"
	errorutil "github.com/projectdiscovery/utils/errors"
)

// unsafeOptions are those nuclei objects/instances/types
// that are required to run nuclei engine but are not thread safe
// hence they are ephemeral and are created on every ExecuteNucleiWithOpts invocation
// in ThreadSafeNucleiEngine
type unsafeOptions struct {
	executerOpts protocols.ExecutorOptions
	engine       *core.Engine
}

// createEphemeralObjects creates ephemeral nuclei objects/instances/types
func createEphemeralObjects(ctx context.Context, base *NucleiEngine, opts *types.Options) (*unsafeOptions, error) {
	u := &unsafeOptions{}
	u.executerOpts = protocols.ExecutorOptions{
		Output:          base.customWriter,
		Options:         opts,
		Progress:        base.customProgress,
		Catalog:         base.catalog,
		IssuesClient:    base.rc,
		RateLimiter:     base.rateLimiter,
		Interactsh:      base.interactshClient,
		HostErrorsCache: base.hostErrCache,
		Colorizer:       aurora.NewAurora(true),
		ResumeCfg:       types.NewResumeCfg(),
		Parser:          base.parser,
		Browser:         base.browserInstance,
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
	if opts.RateLimit == 0 && opts.RateLimitDuration == 0 {
		u.executerOpts.RateLimiter = ratelimit.NewUnlimited(ctx)
	} else {
		u.executerOpts.RateLimiter = ratelimit.New(ctx, uint(opts.RateLimit), opts.RateLimitDuration)
	}
	u.engine = core.New(opts)
	u.engine.SetExecuterOptions(u.executerOpts)
	return u, nil
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
	// default options
	e := &NucleiEngine{
		opts: types.DefaultOptions(),
		mode: threadSafe,
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
func (e *ThreadSafeNucleiEngine) GlobalResultCallback(callback func(event *output.ResultEvent)) {
	e.eng.resultCallbacks = []func(*output.ResultEvent){callback}
}

// ExecuteNucleiWithOptsCtx executes templates on targets and calls callback on each result(only if results are found)
// This method can be called concurrently and it will use some global resources but can be runned parallelly
// by invoking this method with different options and targets
// Note: Not all options are thread-safe. this method will throw error if you try to use non-thread-safe options
func (e *ThreadSafeNucleiEngine) ExecuteNucleiWithOptsCtx(ctx context.Context, targets []string, opts ...NucleiSDKOptions) error {
	baseOpts := *e.eng.opts
	tmpEngine := &NucleiEngine{opts: &baseOpts, mode: threadSafe}
	for _, option := range opts {
		if err := option(tmpEngine); err != nil {
			return err
		}
	}

	// create ephemeral nuclei objects/instances/types using base nuclei engine
	unsafeOpts, err := createEphemeralObjects(ctx, e.eng, tmpEngine.opts)
	if err != nil {
		return err
	}
	// cleanup and stop all resources
	defer closeEphemeralObjects(unsafeOpts)

	// load templates
	workflowLoader, err := workflow.NewLoader(&unsafeOpts.executerOpts)
	if err != nil {
		return errorutil.New("Could not create workflow loader: %s\n", err)
	}
	unsafeOpts.executerOpts.WorkflowLoader = workflowLoader

	store, err := loader.New(loader.NewConfig(tmpEngine.opts, e.eng.catalog, unsafeOpts.executerOpts))
	if err != nil {
		return errorutil.New("Could not create loader client: %s\n", err)
	}
	store.Load()

	inputProvider := provider.NewSimpleInputProviderWithUrls(targets...)

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
