package globalratelimiter

import (
	"sync"

	"go.uber.org/ratelimit"
)

var defaultrwmutex sync.RWMutex
var defaultGlobalRateLimiter GlobalRateLimiter = GlobalRateLimiter{ratesLimiters: make(map[string]ratelimit.Limiter)}

type GlobalRateLimiter struct {
	sync.RWMutex
	ratesLimiters map[string]ratelimit.Limiter
}

func Add(k string, rateLimit int) {
	defaultrwmutex.Lock()
	defer defaultrwmutex.Unlock()

	if rateLimit > 0 {
		defaultGlobalRateLimiter.ratesLimiters[k] = ratelimit.New(rateLimit)
	} else {
		defaultGlobalRateLimiter.ratesLimiters[k] = ratelimit.NewUnlimited()
	}
}

func Take(k string) {
	defaultrwmutex.RLock()
	defer defaultrwmutex.RUnlock()

	defaultGlobalRateLimiter.ratesLimiters[k].Take()
}

func Del(k string, rateLimit int) {
	defaultrwmutex.Lock()
	defer defaultrwmutex.Unlock()

	delete(defaultGlobalRateLimiter.ratesLimiters, k)
}

func New() *GlobalRateLimiter {
	var globalRateLimiter GlobalRateLimiter
	globalRateLimiter.ratesLimiters = make(map[string]ratelimit.Limiter)
	return &globalRateLimiter
}

func (grl *GlobalRateLimiter) Add(k string, rateLimit int) {
	grl.Lock()
	defer grl.Unlock()

	if rateLimit > 0 {
		grl.ratesLimiters[k] = ratelimit.New(rateLimit)
	} else {
		grl.ratesLimiters[k] = ratelimit.NewUnlimited()
	}
}

func (grl *GlobalRateLimiter) Take(k string) {
	grl.RLock()
	defer grl.RUnlock()

	grl.ratesLimiters[k].Take()
}

func (grl *GlobalRateLimiter) Del(k string, rateLimit int) {
	grl.Lock()
	defer grl.Unlock()

	delete(grl.ratesLimiters, k)
}
