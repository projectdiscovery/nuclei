package runner

import (
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/remeh/sizedwaitgroup"
)

const probeBulkSize = 50

// initializeTemplatesHTTPInput initializes the http form of input
// for any loaded http templates if input is in non-standard format.
func (r *Runner) initializeTemplatesHTTPInput() (*hybrid.HybridMap, error) {
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil, errors.Wrap(err, "could not create temporary input file")
	}
	gologger.Info().Msgf("Running httpx on input host")

	var bulkSize = probeBulkSize
	if r.options.BulkSize > probeBulkSize {
		bulkSize = r.options.BulkSize
	}

	httpxOptions := httpx.DefaultOptions
	httpxOptions.RetryMax = r.options.Retries
	httpxOptions.Timeout = time.Duration(r.options.Timeout) * time.Second
	httpxClient, err := httpx.New(&httpxOptions)
	if err != nil {
		return nil, errors.Wrap(err, "could not create httpx client")
	}

	// Probe the non-standard URLs and store them in cache
	swg := sizedwaitgroup.New(bulkSize)
	count := int32(0)
	r.hmapInputProvider.Scan(func(value *contextargs.MetaInput) bool {
		if stringsutil.HasPrefixAny(value.Input, "http://", "https://") {
			return true
		}

		swg.Add()
		go func(input *contextargs.MetaInput) {
			defer swg.Done()

			if result := utils.ProbeURL(input.Input, httpxClient); result != "" {
				atomic.AddInt32(&count, 1)
				_ = hm.Set(input.Input, []byte(result))
			}
		}(value)
		return true
	})
	swg.Wait()

	gologger.Info().Msgf("Found %d URL from httpx", atomic.LoadInt32(&count))
	return hm, nil
}
