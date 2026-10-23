package engine

import (
	"context"
	"errors"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/utils"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/render"
)

// Instance is an isolated browser instance opened for doing operations with it.
type Instance struct {
	browser *Browser
	engine  *rod.Browser

	// redundant due to dependency cycle
	interactsh render.URLSource
	requestLog map[string]string // contains actual request that was sent
}

const browserCleanupTimeout = 5 * time.Second

// NewInstance creates a new instance for the current browser.
//
// The login process is repeated only once for a browser, and the created
// isolated browser instance is used for entire navigation one by one.
//
// Users can also choose to run the login->actions process again
// which uses a new incognito browser instance to run actions.
func (b *Browser) NewInstance() (*Instance, error) {
	return b.newInstanceBrowser(b.engine)
}

// NewInstanceWithContext bounds browser-context creation and all subsequent instance calls.
func (b *Browser) NewInstanceWithContext(ctx context.Context, timeout time.Duration) (*Instance, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, context.Cause(ctx)
	}

	if timeout <= 0 {
		timeout = browserCleanupTimeout
	}
	creationCtx, cancelCreation := context.WithTimeout(b.engine.GetContext(), timeout)
	type result struct {
		instance *Instance
		err      error
	}
	resultCh := make(chan result, 1)
	go func() {
		instance, err := b.newInstanceBrowser(b.engine.Context(creationCtx))
		resultCh <- result{instance: instance, err: err}
	}()

	cleanup := func(instance *Instance) {
		if instance == nil {
			return
		}
		if err := instance.Close(); err != nil {
			gologger.Warning().Msgf("Could not close canceled browser instance: %s", err)
		}
	}

	select {
	case created := <-resultCh:
		cancelCreation()
		if created.err != nil {
			return nil, created.err
		}
		if err := ctx.Err(); err != nil {
			go cleanup(created.instance)
			return nil, context.Cause(ctx)
		}
		created.instance.engine = created.instance.engine.Context(ctx)
		return created.instance, nil
	case <-ctx.Done():
		go func() {
			created := <-resultCh
			cancelCreation()
			if created.err == nil {
				cleanup(created.instance)
			}
		}()
		return nil, context.Cause(ctx)
	}
}

func (b *Browser) newInstanceBrowser(engine *rod.Browser) (*Instance, error) {
	browser, err := engine.Incognito()
	if err != nil {
		return nil, err
	}

	// We use a custom sleeper that sleeps from 100ms to 500 ms waiting
	// for an interaction. Used throughout rod for clicking, etc.
	browser = browser.Sleeper(func() utils.Sleeper { return maxBackoffSleeper(10) })
	return &Instance{browser: b, engine: browser, requestLog: map[string]string{}}, nil
}

// returns a map of [template-defined-urls] -> [actual-request-sent]
// Note: this does not include CORS or other requests while rendering that were not explicitly
// specified in template
func (i *Instance) GetRequestLog() map[string]string {
	return i.requestLog
}

// Close closes all the tabs and pages for a browser instance
func (i *Instance) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), browserCleanupTimeout)
	defer cancel()
	return i.close(ctx)
}

// CloseWithPage closes a page and its isolated browser context within one cleanup deadline.
func (i *Instance) CloseWithPage(page *Page) error {
	ctx, cancel := context.WithTimeout(context.Background(), browserCleanupTimeout)
	defer cancel()
	if page != nil {
		page.close(ctx)
	}
	return i.close(ctx)
}

func (i *Instance) close(ctx context.Context) error {
	return i.engine.Context(ctx).Close()
}

// SetInteractsh client
func (i *Instance) SetInteractsh(interactsh *interactsh.Client) {
	i.interactsh = interactsh
}

// maxBackoffSleeper is a backoff sleeper respecting max backoff values
func maxBackoffSleeper(max int) utils.Sleeper {
	count := 0
	backoffSleeper := utils.BackoffSleeper(100*time.Millisecond, 500*time.Millisecond, nil)

	return func(ctx context.Context) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if count == max {
			return errors.New("max sleep count")
		}
		count++
		return backoffSleeper(ctx)
	}
}
