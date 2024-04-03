package cruisecontrol

import (
	"context"
	"time"

	"github.com/projectdiscovery/ratelimit"
	syncutil "github.com/projectdiscovery/utils/sync"
)

type Options struct {
	RateLimit       RateLimitOptions
	Standard        TypeOptions
	Headless        TypeOptions
	Javascript      JsTypeOptions
	TemplatePayload int
}

type RateLimitOptions struct {
	MaxTokens int
	Duration  time.Duration
}

type TypeOptions struct {
	Concurrency Concurrency
	Durations   Duration
}

type JsTypeOptions struct {
	Concurrency JsConcurrency
	Durations   Duration
}

type Concurrency struct {
	Templates int
	Hosts     int
}

type JsConcurrency struct {
	Pooled    int
	NotPooled int
}

type Duration struct {
	DialTimeout time.Duration
	Timeout     time.Duration
}

type CruiseControl struct {
	Settings    Options
	RateLimiter *ratelimit.Limiter
}

func New(options Options) (*CruiseControl, error) {
	var rateLimiter *ratelimit.Limiter
	if options.RateLimit.MaxTokens == 0 && options.RateLimit.Duration == 0 {
		rateLimiter = ratelimit.NewUnlimited(context.Background())
	} else {
		rateLimiter = ratelimit.New(context.Background(), uint(options.RateLimit.MaxTokens), options.RateLimit.Duration)
	}
	return &CruiseControl{Settings: options, RateLimiter: rateLimiter}, nil
}

func (c *CruiseControl) Standard() TypeOptions {
	return c.Settings.Standard
}

func (c *CruiseControl) Headless() TypeOptions {
	return c.Settings.Headless
}

func (c *CruiseControl) HeadlessTemplates() int {
	return c.Settings.Headless.Concurrency.Templates
}

func (c *CruiseControl) HeadlessHosts() int {
	return c.Settings.Headless.Concurrency.Hosts
}

func (c *CruiseControl) StandardTemplates() int {
	return c.Settings.Standard.Concurrency.Templates
}

func (c *CruiseControl) StandardHosts() int {
	return c.Settings.Standard.Concurrency.Hosts
}

func (c *CruiseControl) Payload() int {
	return c.Settings.TemplatePayload
}

func (c *CruiseControl) StandardTimeout() time.Duration {
	return c.Settings.Standard.Durations.Timeout
}

func (c *CruiseControl) HeadlessTimeout() time.Duration {
	return c.Settings.Headless.Durations.Timeout
}

func (c *CruiseControl) DeprecatedPayload(totalRequests, currentThreads int) int {
	if currentThreads > 0 {
		return currentThreads
	} else {
		return c.Settings.TemplatePayload
	}
}

func (c *CruiseControl) Close() {
	if c.RateLimiter != nil {
		c.RateLimiter.Stop()
		c.RateLimiter = nil
	}
}

func (c *CruiseControl) NewPool(cruiseControlSizeFN func() int) *CruiseControlPool {
	wg, _ := syncutil.New(syncutil.WithSize(cruiseControlSizeFN()))
	return &CruiseControlPool{CruiseControlSizeFN: cruiseControlSizeFN, WaitGroup: wg}
}

type CruiseControlPoolOption func(*CruiseControlPool) error

type CruiseControlPool struct {
	CruiseControlSizeFN func() int
	WaitGroup           *syncutil.AdaptiveWaitGroup
}

func (ccp *CruiseControlPool) Add() {
	size := ccp.CruiseControlSizeFN()
	if ccp.WaitGroup.Size != size {
		ccp.WaitGroup.Resize(size)
	}
	ccp.WaitGroup.Add()
}

func (ccp *CruiseControlPool) Done() {
	ccp.WaitGroup.Done()
}

func (ccp *CruiseControlPool) Wait() {
	ccp.WaitGroup.Wait()
}
