package runner

import (
	"fmt"
	"io"
	"strings"
	"sync/atomic"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/retryablehttp-go"
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

	httpclient, err := httpclientpool.Get(r.options, &httpclientpool.Configuration{})
	if err != nil {
		return nil, errors.Wrap(err, "could not get http client")
	}
	gologger.Info().Msgf("Running httpx on input to execute http based template")

	var bulkSize = probeBulkSize
	if r.options.BulkSize > probeBulkSize {
		bulkSize = r.options.BulkSize
	}
	// Probe the non-standard URLs and store them in cache
	swg := sizedwaitgroup.New(bulkSize)
	count := int32(0)
	r.hmapInputProvider.Scan(func(value *contextargs.MetaInput) bool {
		if strings.HasPrefix(value.Input, "http://") || strings.HasPrefix(value.Input, "https://") {
			return true
		}

		swg.Add()
		go func(input *contextargs.MetaInput) {
			defer swg.Done()

			if result := probeURL(input.Input, httpclient); result != "" {
				atomic.AddInt32(&count, 1)
				_ = hm.Set(input.String(), []byte(result))
			}
		}(value)
		return true
	})
	swg.Wait()

	gologger.Info().Msgf("Discovered %d URL from input", atomic.LoadInt32(&count))
	return hm, nil
}

var (
	drainReqSize = int64(8 * 1024)
	httpSchemes  = []string{"https", "http"}
)

// probeURL probes the scheme for a URL. first HTTPS is tried
// and if any errors occur http is tried. If none succeeds, probing
// is abandoned for such URLs.
func probeURL(input string, httpclient *retryablehttp.Client) string {
	for _, scheme := range httpSchemes {
		formedURL := fmt.Sprintf("%s://%s", scheme, input)
		resp, err := httpclient.Get(formedURL)
		if resp != nil {
			_, _ = io.CopyN(io.Discard, resp.Body, drainReqSize)
			resp.Body.Close()
		}
		if err != nil {
			continue
		}
		return formedURL
	}
	return ""
}
