package runner

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httprespcache"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

// Without -strict-probe or -tech-filter the SDK hook changes nothing.
func TestAttachScanPlanNoop(t *testing.T) {
	opts := types.DefaultOptions()
	opts.ScanStrategy = "auto"
	engine := core.New(opts)
	engine.SetExecuterOptions(&protocols.ExecutorOptions{Options: opts})
	ip := provider.NewSimpleInputProviderWithUrls(opts.ExecutionId, "http://127.0.0.1:1")

	AttachScanPlan(opts, ip, nil, engine, nil)()
	require.Equal(t, "auto", opts.ScanStrategy)
	require.Nil(t, engine.ExecuterOptions().TargetScope)
}

// The SDK engine is reused across scans, so the hook must leave its options
// and its response cache as they were before the scan.
func TestAttachScanPlanRestoresEngineState(t *testing.T) {
	opts := types.DefaultOptions()
	opts.ScanStrategy = "auto"
	opts.TechFilter = true
	cache := httprespcache.New()
	engine := core.New(opts)
	engine.SetExecuterOptions(&protocols.ExecutorOptions{Options: opts, HTTPResponseCache: cache})
	ip := provider.NewSimpleInputProviderWithUrls(opts.ExecutionId, "http://127.0.0.1:1")

	cleanup := AttachScanPlan(opts, ip, nil, engine, nil)
	require.NotEqual(t, "auto", opts.ScanStrategy, "the plan resolves the auto strategy for the scan")
	cleanup()
	require.Equal(t, "auto", opts.ScanStrategy)
	require.Same(t, cache, engine.ExecuterOptions().HTTPResponseCache)
	require.Nil(t, engine.ExecuterOptions().TargetScope)
}
