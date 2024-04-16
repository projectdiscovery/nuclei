package runner

import (
	"sync/atomic"
	"time"

	"github.com/effluxio/nuclei/v3/pkg/input/provider"
	"github.com/effluxio/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/effluxio/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/effluxio/nuclei/v3/pkg/utils"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/httpx/common/httpx"
	stringsutil "github.com/projectdiscovery/utils/strings"
	syncutil "github.com/projectdiscovery/utils/sync"
)

var GlobalProbeBulkSize = 50

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
	gologger.Info().Msgf("Running httpx on input host")

	var bulkSize = GlobalProbeBulkSize
	if r.options.BulkSize > GlobalProbeBulkSize {
		bulkSize = r.options.BulkSize
	}

	httpxOptions := httpx.DefaultOptions
	httpxOptions.RetryMax = r.options.Retries
	httpxOptions.Timeout = time.Duration(r.options.Timeout) * time.Second
	httpxOptions.NetworkPolicy = protocolstate.NetworkPolicy
	httpxClient, err := httpx.New(&httpxOptions)
	if err != nil {
		return nil, errors.Wrap(err, "could not create httpx client")
	}

	shouldFollowGlobalProbeBulkSize := bulkSize == GlobalProbeBulkSize

	// Probe the non-standard URLs and store them in cache
	swg, err := syncutil.New(syncutil.WithSize(bulkSize))
	if err != nil {
		return nil, errors.Wrap(err, "could not create adaptive group")
	}
	var count atomic.Int32
	r.inputProvider.Iterate(func(value *contextargs.MetaInput) bool {
		if stringsutil.HasPrefixAny(value.Input, "http://", "https://") {
			return true
		}

		if shouldFollowGlobalProbeBulkSize && swg.Size != GlobalProbeBulkSize {
			swg.Resize(GlobalProbeBulkSize)
		}

		swg.Add()
		go func(input *contextargs.MetaInput) {
			defer swg.Done()

			if result := utils.ProbeURL(input.Input, httpxClient); result != "" {
				count.Add(1)
				_ = hm.Set(input.Input, []byte(result))
			}
		}(value)
		return true
	})
	swg.Wait()

	gologger.Info().Msgf("Found %d URL from httpx", count.Load())
	return hm, nil
}
