package contextargs

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMetaInputMarshalAndUnmarshalString(t *testing.T) {
	input := NewMetaInput()
	input.Input = "https://example.com"
	input.CustomIP = "192.0.2.10"

	encoded, err := input.MarshalString()
	require.NoError(t, err)
	require.Equal(t, "{\"input\":\"https://example.com\",\"customIP\":\"192.0.2.10\"}\n", encoded)

	decoded := NewMetaInput()
	require.NoError(t, decoded.Unmarshal(encoded))
	require.Equal(t, input.Input, decoded.Input)
	require.Equal(t, input.CustomIP, decoded.CustomIP)
}

func TestGetCopyIfHostOutdated(t *testing.T) {
	t.Run("same host and scheme returns original context", func(t *testing.T) {
		ctx := NewWithInput(context.Background(), "http://127.0.0.1:3000")
		updated := GetCopyIfHostOutdated(ctx, "http://127.0.0.1:3000/api/v1")
		require.Same(t, ctx, updated)
		require.Equal(t, "127.0.0.1:3000", updated.MetaInput.Address())
	})

	t.Run("custom port returns updated context with scheme preserved", func(t *testing.T) {
		ctx := NewWithInput(context.Background(), "http://127.0.0.1:3000")
		updated := GetCopyIfHostOutdated(ctx, "http://127.0.0.1:8080/probe")
		require.NotSame(t, ctx, updated)
		require.Equal(t, "http://127.0.0.1:8080", updated.MetaInput.Input)
		require.Equal(t, "127.0.0.1:8080", updated.MetaInput.Address())
		require.Equal(t, "127.0.0.1:3000", ctx.MetaInput.Address())
	})

	t.Run("https scheme without explicit port resolves to 443", func(t *testing.T) {
		ctx := NewWithInput(context.Background(), "http://example.com:3000")
		updated := GetCopyIfHostOutdated(ctx, "https://example.com/login")
		require.NotSame(t, ctx, updated)
		require.Equal(t, "https://example.com", updated.MetaInput.Input)
		require.Equal(t, "example.com:443", updated.MetaInput.Address())
	})

	t.Run("scheme change on default port detects port change", func(t *testing.T) {
		ctx := NewWithInput(context.Background(), "http://example.com")
		updated := GetCopyIfHostOutdated(ctx, "https://example.com/secure")
		require.NotSame(t, ctx, updated)
		require.Equal(t, "https://example.com", updated.MetaInput.Input)
		require.Equal(t, "example.com:443", updated.MetaInput.Address())
	})
}
