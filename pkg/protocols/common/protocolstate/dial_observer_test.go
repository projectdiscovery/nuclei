package protocolstate

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDialResultReachesOnlyTheObservingContext(t *testing.T) {
	var address string
	var got error
	ctx := WithDialObserver(context.Background(), func(a string, err error) { address, got = a, err })

	refused := errors.New("connection refused")
	reportDialResult(ctx, "acme.test", "22", refused)
	require.Equal(t, "acme.test:22", address)
	require.ErrorIs(t, got, refused)

	reportDialResult(ctx, "[::1]", "22", nil)
	require.Equal(t, "[::1]:22", address, "fastdialer keeps the brackets on an IPv6 host")
	require.NoError(t, got)

	require.NotPanics(t, func() { reportDialResult(context.Background(), "acme.test", "22", refused) })
}
