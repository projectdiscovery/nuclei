package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/cdp"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/stretchr/testify/require"
)

var errCDPCallBlocked = errors.New("cdp call remained blocked")

type blockingCDPClient struct {
	method string
	wait   time.Duration
	events chan *cdp.Event
}

func newBlockingCDPClient(method string, wait time.Duration) *blockingCDPClient {
	return &blockingCDPClient{method: method, wait: wait, events: make(chan *cdp.Event)}
}

func (c *blockingCDPClient) Event() <-chan *cdp.Event {
	return c.events
}

func (c *blockingCDPClient) Call(ctx context.Context, _ string, method string, _ interface{}) ([]byte, error) {
	if method != c.method {
		return []byte("{}"), nil
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(c.wait):
		return nil, errCDPCallBlocked
	}
}

func TestRunCancelsBlockedPageCreation(t *testing.T) {
	client := newBlockingCDPClient("Target.createTarget", 500*time.Millisecond)
	instance := &Instance{
		browser: &Browser{},
		engine:  rod.New().Client(client),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, _, err := instance.Run(
		contextargs.NewWithInput(ctx, "http://example.com"),
		nil,
		nil,
		&Options{Timeout: time.Second},
	)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), 200*time.Millisecond)
}
