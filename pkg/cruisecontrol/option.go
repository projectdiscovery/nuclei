package cruisecontrol

import (
	"time"

	jsdefaults "github.com/projectdiscovery/nuclei/v3/pkg/js/compiler/defaults"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func ParseOptionsFrom(options *types.Options) Options {
	opts := Options{
		RateLimit: RateLimitOptions{
			MaxTokens: options.RateLimit,
			Duration:  options.RateLimitDuration,
		},
		Standard: TypeOptions{
			Concurrency: Concurrency{
				Templates: options.TemplateThreads,
				Hosts:     options.BulkSize,
			},
			Durations: Duration{
				Timeout:     time.Duration(options.Timeout) * time.Second,
				DialTimeout: options.DialerTimeout,
			},
		},
		Headless: TypeOptions{
			Concurrency: Concurrency{
				Templates: options.HeadlessTemplateThreads,
				Hosts:     options.HeadlessBulkSize,
			},
			Durations: Duration{
				Timeout:     time.Duration(options.PageTimeout) * time.Second,
				DialTimeout: options.DialerTimeout,
			},
		},
		TemplatePayload: options.PayloadConcurrency,
	}

	// -- Javascript
	// adjust javascript settings as per previous logic
	if options.Timeout >= 10 {
		opts.Javascript.Durations.Timeout = time.Duration(options.Timeout) * time.Second
	} else {
		opts.Javascript.Durations.Timeout = time.Duration(jsdefaults.Timeout) * time.Second
	}

	if options.JsConcurrency < jsdefaults.Total {
		opts.Javascript.Concurrency.Pooled = jsdefaults.Pooled
		opts.Javascript.Concurrency.NotPooled = jsdefaults.NotPooled
	} else {
		opts.Javascript.Concurrency.Pooled = options.JsConcurrency
		opts.Javascript.Concurrency.NotPooled = opts.Javascript.Concurrency.Pooled - jsdefaults.NotPooled
	}

	return opts
}
