package cruisecontrol

import "github.com/projectdiscovery/nuclei/v3/pkg/types"

func ParseOptionsFrom(options *types.Options) Options {
	opts := Options{
		RateLimit: RateLimitOptions{
			MaxTokens: options.RateLimit,
			Duration:  options.RateLimitDuration,
		},
		Standard: Concurrency{
			Templates: options.TemplateThreads,
			Hosts:     options.BulkSize,
		},
		Headless: Concurrency{
			Templates: options.HeadlessTemplateThreads,
			Hosts:     options.HeadlessBulkSize,
		},
		JavascriptTemplates: options.JsConcurrency,
		TemplatePayload:     options.PayloadConcurrency,
	}

	return opts
}
