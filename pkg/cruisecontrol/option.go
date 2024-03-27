package cruisecontrol

import (
	"time"

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
		JavascriptTemplates: options.JsConcurrency,
		TemplatePayload:     options.PayloadConcurrency,
	}

	return opts
}
