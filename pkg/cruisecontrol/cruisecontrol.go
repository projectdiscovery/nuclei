package cruisecontrol

import (
	"context"
	"time"

	"github.com/projectdiscovery/ratelimit"
)

type Options struct {
	RateLimit RateLimitOptions
}

type RateLimitOptions struct {
	MaxTokens int
	Duration  time.Duration
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

func (c *CruiseControl) Close() {
	c.RateLimiter.Stop()
}
