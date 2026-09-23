package http

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types/scanstrategy"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestShouldDisableKeepAliveForHTTPProxy(t *testing.T) {
	opts := types.DefaultOptions()
	opts.AliveHttpProxy = "http://127.0.0.1:8080"
	opts.ScanStrategy = scanstrategy.TemplateSpray.String()
	require.True(t, shouldDisableKeepAliveForHTTPProxy(&Request{}, &protocols.ExecutorOptions{Options: opts}))

	opts.ScanStrategy = scanstrategy.HostSpray.String()
	require.False(t, shouldDisableKeepAliveForHTTPProxy(&Request{}, &protocols.ExecutorOptions{Options: opts}))
	require.False(t, shouldDisableKeepAliveForHTTPProxy(&Request{Threads: 10}, &protocols.ExecutorOptions{Options: opts}))
}
