package engine

import (
	"context"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/stretchr/testify/require"
)

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
