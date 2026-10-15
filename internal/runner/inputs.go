package runner

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	stringsutil "github.com/projectdiscovery/utils/strings"
	syncutil "github.com/projectdiscovery/utils/sync"
)

// Minimum number of hosts that need httpx probing before we emit periodic
// progress lines. Keeps small scans unchanged.
const httpxProbeProgressMinTargets = 1000

// initializeTemplatesHTTPInput initializes the http form of input
// for any loaded http templates if input is in non-standard format.
func (r *Runner) initializeTemplatesHTTPInput() (*hybrid.HybridMap, error) {
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil, errors.Wrap(err, "could not create temporary input file")
	}
	if r.inputProvider.InputType() == provider.MultiFormatInputProvider {
		// currently http probing for input mode types is not supported
		return hm, nil
	}
	r.Logger.Info().Msgf("Running httpx on input host")

	httpxOptions := httpx.DefaultOptions
	if r.options.AliveHttpProxy != "" {
		httpxOptions.Proxy = r.options.AliveHttpProxy
	} else if r.options.AliveSocksProxy != "" {
		httpxOptions.Proxy = r.options.AliveSocksProxy
	}
	httpxOptions.RetryMax = r.options.Retries
	httpxOptions.Timeout = time.Duration(r.options.Timeout) * time.Second

	dialers := protocolstate.GetDialersWithId(r.options.ExecutionId)
	if dialers == nil {
		return nil, fmt.Errorf("dialers not initialized for %s", r.options.ExecutionId)
	}

	httpxOptions.NetworkPolicy = dialers.NetworkPolicy
	httpxClient, err := httpx.New(&httpxOptions)
	if err != nil {
		return nil, errors.Wrap(err, "could not create httpx client")
	}

	// Probe the non-standard URLs and store them in cache
	swg, err := syncutil.New(syncutil.WithSize(r.options.BulkSize))
	if err != nil {
		return nil, errors.Wrap(err, "could not create adaptive group")
	}
	var alive atomic.Int32
	var probed atomic.Int32
	var probeTotal int

	r.inputProvider.Iterate(func(value *contextargs.MetaInput) bool {
		if stringsutil.HasPrefixAny(value.Input, "http://", "https://") {
			return true
		}

		if r.options.ProbeConcurrency > 0 && swg.Size != r.options.ProbeConcurrency {
			if err := swg.Resize(context.Background(), r.options.ProbeConcurrency); err != nil {
				r.Logger.Error().Msgf("Could not resize workpool: %s\n", err)
			}
		}

		probeTotal++
		swg.Add()
		go func(input *contextargs.MetaInput) {
			defer swg.Done()
			defer probed.Add(1)

			if result := utils.ProbeURL(input.Input, httpxClient); result != "" {
				alive.Add(1)
				_ = hm.Set(input.Input, []byte(result))
			}
		}(value)
		return true
	})

	// Start progress only after enqueue so we know the total; ticker runs during Wait.
	if stop := r.startHTTPXProbeProgress(probeTotal, &probed, &alive); stop != nil {
		defer stop()
	}

	swg.Wait()

	r.Logger.Info().Msgf("Found %d URL from httpx", alive.Load())
	return hm, nil
}

// startHTTPXProbeProgress optionally logs probe progress for large input sets
// when -stats is enabled. Returns a stop func, or nil when progress is inactive.
func (r *Runner) startHTTPXProbeProgress(probeTotal int, probed, alive *atomic.Int32) func() {
	if probeTotal < httpxProbeProgressMinTargets || !r.options.EnableProgressBar {
		return nil
	}

	interval := time.Duration(r.options.StatsInterval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	r.Logger.Info().Msgf("httpx probe progress enabled for %d hosts (interval %s)", probeTotal, interval)

	ctx, cancel := context.WithCancel(context.Background())
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.Logger.Info().Msgf(
					"[httpx] probe progress: %d/%d (alive: %d)",
					probed.Load(), probeTotal, alive.Load(),
				)
			}
		}
	}()
	return cancel
}
