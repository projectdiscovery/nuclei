package engine

import (
	"context"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/cdp"
	"github.com/go-rod/rod/lib/proto"
	"github.com/stretchr/testify/require"
)

type cleanupCDPClient struct {
	events      chan *cdp.Event
	contextErrs chan error
}

type lateCreateCDPClient struct {
	events   chan *cdp.Event
	disposed chan struct{}
	delay    time.Duration
}

func (c *lateCreateCDPClient) Event() <-chan *cdp.Event {
	return c.events
}

func (c *lateCreateCDPClient) Call(_ context.Context, _ string, method string, _ interface{}) ([]byte, error) {
	switch method {
	case "Target.createBrowserContext":
		time.Sleep(c.delay)
		return []byte(`{"browserContextId":"context-id"}`), nil
	case "Target.disposeBrowserContext":
		select {
		case c.disposed <- struct{}{}:
		default:
		}
	}
	return []byte("{}"), nil
}

func (c *cleanupCDPClient) Event() <-chan *cdp.Event {
	return c.events
}

func (c *cleanupCDPClient) Call(ctx context.Context, _ string, method string, _ interface{}) ([]byte, error) {
	if method == "Target.disposeBrowserContext" {
		c.contextErrs <- ctx.Err()
	}
	return []byte("{}"), nil
}

func TestNewInstanceWithContextCancelsBlockedBrowserContextCreation(t *testing.T) {
	client := newBlockingCDPClient("Target.createBrowserContext", 500*time.Millisecond)
	browser := &Browser{engine: rod.New().Client(client)}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := browser.NewInstanceWithContext(ctx, time.Second)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), 200*time.Millisecond)
}

func TestNewInstanceWithContextDisposesContextCreatedAfterCancellation(t *testing.T) {
	client := &lateCreateCDPClient{
		events:   make(chan *cdp.Event),
		disposed: make(chan struct{}, 1),
		delay:    50 * time.Millisecond,
	}
	browser := &Browser{engine: rod.New().Client(client)}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := browser.NewInstanceWithContext(ctx, time.Second)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), 100*time.Millisecond)

	select {
	case <-client.disposed:
	case <-time.After(time.Second):
		t.Fatal("browser context created after cancellation was not disposed")
	}
}

func TestInstanceCloseUsesLiveCleanupContext(t *testing.T) {
	client := &cleanupCDPClient{
		events:      make(chan *cdp.Event),
		contextErrs: make(chan error, 1),
	}
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	browser := rod.New().Client(client).Context(canceledCtx)
	browser.BrowserContextID = proto.BrowserBrowserContextID("context-id")
	instance := &Instance{engine: browser}

	require.NoError(t, instance.Close())
	require.NoError(t, <-client.contextErrs)
}
