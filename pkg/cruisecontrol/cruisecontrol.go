package cruisecontrol

import (
	"context"
	"time"

	"github.com/projectdiscovery/ratelimit"
)

type Options struct {
	RateLimit           RateLimitOptions
	Standard            Concurrency
	Headless            Concurrency
	JavascriptTemplates int
	TemplatePayload     int
}

type RateLimitOptions struct {
	MaxTokens int
	Duration  time.Duration
}

type Concurrency struct {
	Templates int
	Hosts     int
}

type CruiseControl struct {
	options     Options
	RateLimiter *ratelimit.Limiter
}

func New(options Options) (*CruiseControl, error) {
	var rateLimiter *ratelimit.Limiter
	if options.RateLimit.MaxTokens == 0 && options.RateLimit.Duration == 0 {
		rateLimiter = ratelimit.NewUnlimited(context.Background())
	} else {
		rateLimiter = ratelimit.New(context.Background(), uint(options.RateLimit.MaxTokens), options.RateLimit.Duration)
	}
	return &CruiseControl{options: options, RateLimiter: rateLimiter}, nil
}

func (c *CruiseControl) Standard() Concurrency {
	return c.options.Standard
}

func (c *CruiseControl) Headless() Concurrency {
	return c.options.Headless
}

func (c *CruiseControl) Javascript() int {
	return c.options.JavascriptTemplates
}

func (c *CruiseControl) Payload() int {
	return c.options.TemplatePayload
}

func (c *CruiseControl) Close() {
	c.RateLimiter.Stop()
}
