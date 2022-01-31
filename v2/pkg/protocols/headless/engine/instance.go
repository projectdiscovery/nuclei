package engine

import (
	"context"
	"errors"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/utils"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
)

// Instance is an isolated browser instance opened for doing operations with it.
type Instance struct {
	browser *Browser
	engine  *rod.Browser

	// redundant due to dependency cycle
	interactsh *interactsh.Client
}

// NewInstance creates a new instance for the current browser.
//
// The login process is repeated only once for a browser, and the created
// isolated browser instance is used for entire navigation one by one.
//
// Users can also choose to run the login->actions process again
// which uses a new incognito browser instance to run actions.
func (b *Browser) NewInstance() (*Instance, error) {
	browser, err := b.engine.Incognito()
	if err != nil {
		return nil, err
	}

	// We use a custom sleeper that sleeps from 100ms to 500 ms waiting
	// for an interaction. Used throughout rod for clicking, etc.
	browser = browser.Sleeper(func() utils.Sleeper { return maxBackoffSleeper(10) })
	return &Instance{browser: b, engine: browser}, nil
}

// Close closes all the tabs and pages for a browser instance
func (i *Instance) Close() error {
	return i.engine.Close()
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
