package runner

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/corpix/uarand"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
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
		if strings.HasPrefix(value.Input, "http://") || strings.HasPrefix(value.Input, "https://") {
			return true
		}

		swg.Add()
		go func(input *contextargs.MetaInput) {
			defer swg.Done()

			if result := probeURL(input.Input, httpxClient); result != "" {
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

var (
	httpSchemes = []string{"https", "http"}
)

// probeURL probes the scheme for a URL. first HTTPS is tried
// and if any errors occur http is tried. If none succeeds, probing
// is abandoned for such URLs.
func probeURL(input string, httpxclient *httpx.HTTPX) string {
	for _, scheme := range httpSchemes {
		formedURL := fmt.Sprintf("%s://%s", scheme, input)
		req, err := httpxclient.NewRequest(http.MethodHead, formedURL)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", uarand.GetRandom())

		if _, err = httpxclient.Do(req, httpx.UnsafeOptions{}); err != nil {
			continue
		}
		return formedURL
	}
	return ""
}
