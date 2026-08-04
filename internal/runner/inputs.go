package runner

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	stringsutil "github.com/projectdiscovery/utils/strings"
	syncutil "github.com/projectdiscovery/utils/sync"
)

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
	var count atomic.Int32
	var processed atomic.Int64
	stopProgress := r.startHTTPProbeProgress(r.inputProvider.Count(), &processed)
	defer stopProgress()
	r.inputProvider.Iterate(func(value *contextargs.MetaInput) bool {
		if stringsutil.HasPrefixAny(value.Input, "http://", "https://") {
			processed.Add(1)
			return true
		}

		if r.options.ProbeConcurrency > 0 && swg.Size != r.options.ProbeConcurrency {
			if err := swg.Resize(context.Background(), r.options.ProbeConcurrency); err != nil {
				r.Logger.Error().Msgf("Could not resize workpool: %s\n", err)
			}
		}

		swg.Add()
		go func(input *contextargs.MetaInput) {
			defer swg.Done()
			defer processed.Add(1)

			if r.options.Debug || r.options.DebugRequests {
				gologger.Print().Msgf("[httpx] Probing input %s\n", input.Input)
			}
			result := utils.ProbeURL(input.Input, httpxClient)
			if r.options.Debug || r.options.DebugResponse {
				if result == "" {
					gologger.Print().Msgf("[httpx] No HTTP service found for %s\n", input.Input)
				} else {
					gologger.Print().Msgf("[httpx] Resolved %s to %s\n", input.Input, result)
				}
			}
			if result != "" {
				count.Add(1)
				_ = hm.Set(input.Input, []byte(result))
			}
		}(value)
		return true
	})
	swg.Wait()

	r.Logger.Info().Msgf("Found %d URL from httpx", count.Load())
	return hm, nil
}

// startHTTPProbeProgress reports progress for the input-probing phase. The
// regular scan progress ticker is initialized by the execution engine after
// probing, which can leave long-running scans with no visible progress while
// tens of thousands of non-URL inputs are checked by httpx.
func (r *Runner) startHTTPProbeProgress(total int64, processed *atomic.Int64) func() {
	if !r.options.EnableProgressBar || r.options.StatsInterval <= 0 || total <= 0 {
		return func() {}
	}

	interval := time.Duration(r.options.StatsInterval) * time.Second
	startedAt := time.Now()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_, _ = fmt.Fprintln(os.Stderr, formatHTTPProbeProgress(processed.Load(), total, time.Since(startedAt)))
			case <-stop:
				return
			}
		}
	}()

	return func() {
		close(stop)
		wg.Wait()
	}
}

func formatHTTPProbeProgress(processed, total int64, elapsed time.Duration) string {
	if processed > total {
		processed = total
	}
	percent := float64(processed) / float64(total) * 100
	var rps float64
	if elapsed > 0 {
		rps = float64(processed) / elapsed.Seconds()
	}
	eta := time.Duration(0)
	if rps > 0 && processed < total {
		eta = time.Duration(float64(total-processed)/rps) * time.Second
	}
	return fmt.Sprintf("[httpx] | Hosts: %d/%d (%.0f%%) | RPS: %.0f | ETA: %s", processed, total, percent, rps, shortDur(eta))
}
