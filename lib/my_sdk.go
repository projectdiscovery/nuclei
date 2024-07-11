package nuclei

import (
	"context"
	"fmt"
	"github.com/secoba/nuclei/v3/pkg/core"
	"github.com/secoba/nuclei/v3/pkg/input/provider"
	"github.com/secoba/nuclei/v3/pkg/output"
	"github.com/secoba/nuclei/v3/pkg/templates"
	"github.com/secoba/nuclei/v3/pkg/types"
)

func NewNucleiEngineCtx2(ctx context.Context, opts ...NucleiSDKOptions) (*NucleiEngine, error) {
	// default options
	e := &NucleiEngine{
		opts: types.DefaultOptions(),
		mode: singleInstance,
	}
	for _, option := range opts {
		if err := option(e); err != nil {
			return nil, err
		}
	}
	if err := e.initMy(ctx); err != nil {
		return nil, err
	}
	return e, nil
}

// ExecuteNucleiWithOptsCtx2 executes templates on targets and calls callback on each result(only if results are found)
// This method can be called concurrently and it will use some global resources but can be runned parallelly
// by invoking this method with different options and targets
// Note: Not all options are thread-safe. this method will throw error if you try to use non-thread-safe options
func (e *NucleiEngine) ExecuteNucleiWithOptsCtx2(ctx context.Context, targets []string, templates []*templates.Template, opts ...NucleiSDKOptions) error {
	for _, option := range opts {
		if err := option(e); err != nil {
			return err
		}
	}

	// create ephemeral nuclei objects/instances/types using base nuclei engine
	unsafeOpts, err := createEphemeralObjects(ctx, e, e.opts)
	if err != nil {
		return err
	}
	// cleanup and stop all resources
	defer closeEphemeralObjects(unsafeOpts)

	inputProvider := provider.NewSimpleInputProviderWithUrls(targets...)

	if inputProvider.Count() == 0 {
		return ErrNoTargetsAvailable
	}

	engine := core.New(e.opts)
	engine.SetExecuterOptions(e.executerOpts)

	//_ = engine.Execute(ctx, templates, inputProvider)
	//_ = engine.ExecuteScanWithOpts(ctx, templates, inputProvider, false)
	engine.ExecuteWithResults(ctx, templates, inputProvider, func(event *output.ResultEvent) {
		fmt.Println(event)
	})
	engine.WorkPool().Wait()

	return nil
}
