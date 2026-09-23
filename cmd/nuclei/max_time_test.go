package main

import (
	"testing"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/stretchr/testify/require"
)

// Ensures nuclei's goflags dependency still exposes AddCommonFlags / -max-time,
// which is what cmd/nuclei wires via flagSet.AddCommonFlags().
func TestMaxTimeCommonFlagAvailable(t *testing.T) {
	flagSet := goflags.NewFlagSet()
	common := flagSet.AddCommonFlags()
	require.NotNil(t, common)

	require.NoError(t, flagSet.Parse("-max-time", "1h30m"))
	require.Equal(t, 90*time.Minute, common.MaxTime)

	flagSet = goflags.NewFlagSet()
	common = flagSet.AddCommonFlags()
	require.NoError(t, flagSet.Parse("-mt", "45s"))
	require.Equal(t, 45*time.Second, common.MaxTime)
}
