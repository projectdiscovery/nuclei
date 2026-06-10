package utils

import (
	"context"
	"testing"
	"time"

	"github.com/Mzack9999/goja"
	"github.com/stretchr/testify/require"
)

func TestNucleiJSContextFallback(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		ctx := (*NucleiJS)(nil).Context()
		require.NotNil(t, ctx)
		require.NoError(t, ctx.Err())
	})

	t.Run("missing runtime context", func(t *testing.T) {
		ctx := NewNucleiJS(goja.New()).Context()
		require.NotNil(t, ctx)
		require.NoError(t, ctx.Err())
	})
}

func TestNucleiJSContextUsesRuntimeValue(t *testing.T) {
	runtime := goja.New()
	expected, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	runtime.SetContextValue("ctx", expected)

	ctx := NewNucleiJS(runtime).Context()
	require.Same(t, expected, ctx)

	deadline, ok := ctx.Deadline()
	require.True(t, ok)
	expectedDeadline, _ := expected.Deadline()
	require.Equal(t, expectedDeadline, deadline)
}
