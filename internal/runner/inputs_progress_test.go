package runner

import (
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestHTTPXProbeProgressRespectsDisabledInterval(t *testing.T) {
	var probed, alive atomic.Int32
	for _, interval := range []int{0, -1} {
		options := types.DefaultOptions()
		options.EnableProgressBar = true
		options.StatsInterval = interval
		r := &Runner{options: options, Logger: gologger.DefaultLogger}
		require.Nil(t, r.startHTTPXProbeProgress(httpxProbeProgressMinTargets, &probed, &alive), "interval %d", interval)
	}

	options := types.DefaultOptions()
	options.EnableProgressBar = true
	options.StatsInterval = 5
	r := &Runner{options: options, Logger: gologger.DefaultLogger}
	stop := r.startHTTPXProbeProgress(httpxProbeProgressMinTargets, &probed, &alive)
	require.NotNil(t, stop)
	stop()
}
