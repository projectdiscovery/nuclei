package core

import (
	"context"
	"fmt"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	syncutil "github.com/projectdiscovery/utils/sync"
)

// WorkPool implements an execution pool for executing different
// types of task with different concurrency requirements.
//
// It also allows Configuration of such requirements. This is used
// for per-module like separate headless concurrency etc.
type WorkPool struct {
	Headless *syncutil.AdaptiveWaitGroup
	Default  *syncutil.AdaptiveWaitGroup
	config   WorkPoolConfig
}

// WorkPoolConfig is the configuration for work pool
type WorkPoolConfig struct {
	// InputConcurrency is the concurrency for inputs values.
	InputConcurrency int
	// TypeConcurrency is the concurrency for the request type templates.
	TypeConcurrency int
	// HeadlessInputConcurrency is the concurrency for headless inputs values.
	HeadlessInputConcurrency int
	// TypeConcurrency is the concurrency for the headless request type templates.
	HeadlessTypeConcurrency int
}

// NewWorkPool returns a new WorkPool instance
func NewWorkPool(config WorkPoolConfig) *WorkPool {
	return &WorkPool{
		config:   config,
		Headless: newPool(config.HeadlessTypeConcurrency),
		Default:  newPool(config.TypeConcurrency),
	}
}

// newPool returns a pool of size, or of one when size is below 1.
// syncutil.New returns a nil pool for a size below 1, which the scan would
// dereference.
func newPool(size int) *syncutil.AdaptiveWaitGroup {
	size = max(size, 1)

	pool, err := syncutil.New(syncutil.WithSize(size))
	if err != nil {
		// The size is at least 1, so this cannot happen. Stopping here beats
		// handing the scan a nil pool.
		panic(fmt.Sprintf("could not create work pool of size %d: %s", size, err))
	}

	return pool
}

// Wait waits for all the work pool wait groups to finish
func (w *WorkPool) Wait() {
	w.Default.Wait()
	w.Headless.Wait()
}

// InputPool returns a work pool for an input type
func (w *WorkPool) InputPool(templateType types.ProtocolType) *syncutil.AdaptiveWaitGroup {
	var count int
	if templateType == types.HeadlessProtocol {
		count = w.config.HeadlessInputConcurrency
	} else {
		count = w.config.InputConcurrency
	}

	return newPool(count)
}

func (w *WorkPool) RefreshWithConfig(config WorkPoolConfig) {
	w.RefreshWithConfigContext(context.Background(), config)
}

func (w *WorkPool) RefreshWithConfigContext(ctx context.Context, config WorkPoolConfig) {
	if w.config.TypeConcurrency != config.TypeConcurrency {
		w.config.TypeConcurrency = config.TypeConcurrency
	}
	if w.config.HeadlessTypeConcurrency != config.HeadlessTypeConcurrency {
		w.config.HeadlessTypeConcurrency = config.HeadlessTypeConcurrency
	}
	if w.config.InputConcurrency != config.InputConcurrency {
		w.config.InputConcurrency = config.InputConcurrency
	}
	if w.config.HeadlessInputConcurrency != config.HeadlessInputConcurrency {
		w.config.HeadlessInputConcurrency = config.HeadlessInputConcurrency
	}
	w.Refresh(ctx)
}

func (w *WorkPool) Refresh(ctx context.Context) {
	// newPool sized the pools to at least 1, so compare against the same bound.
	typeConcurrency := max(w.config.TypeConcurrency, 1)
	headlessTypeConcurrency := max(w.config.HeadlessTypeConcurrency, 1)

	if w.Default.Size != typeConcurrency {
		err := w.Default.Resize(ctx, typeConcurrency)
		if err != nil {
			gologger.Warning().Msgf("Could not resize workpool: %s\n", err)
		}
	}

	if w.Headless.Size != headlessTypeConcurrency {
		err := w.Headless.Resize(ctx, headlessTypeConcurrency)
		if err != nil {
			gologger.Warning().Msgf("Could not resize workpool: %s\n", err)
		}
	}
}
