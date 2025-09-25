package cache

import (
	"regexp"
	"sync"

	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/gcache"
)

var (
	initOnce sync.Once
	mu       sync.RWMutex

	regexCap = 4096
	dslCap   = 4096

	regexCache gcache.Cache[string, *regexp.Regexp]
	dslCache   gcache.Cache[string, *govaluate.EvaluableExpression]
)

func initCaches() {
	initOnce.Do(func() {
		regexCache = gcache.New[string, *regexp.Regexp](regexCap).LRU().Build()
		dslCache = gcache.New[string, *govaluate.EvaluableExpression](dslCap).LRU().Build()
	})
}

func SetCapacities(regexCapacity, dslCapacity int) {
	// ensure caches are initialized under initOnce, so later Regex()/DSL() won't re-init
	initCaches()

	mu.Lock()
	defer mu.Unlock()

	if regexCapacity > 0 {
		regexCap = regexCapacity
	}
	if dslCapacity > 0 {
		dslCap = dslCapacity
	}
	if regexCapacity <= 0 && dslCapacity <= 0 {
		return
	}
	// rebuild caches with new capacities
	regexCache = gcache.New[string, *regexp.Regexp](regexCap).LRU().Build()
	dslCache = gcache.New[string, *govaluate.EvaluableExpression](dslCap).LRU().Build()
}

func Regex() gcache.Cache[string, *regexp.Regexp] {
	initCaches()
	mu.RLock()
	defer mu.RUnlock()
	return regexCache
}

func DSL() gcache.Cache[string, *govaluate.EvaluableExpression] {
	initCaches()
	mu.RLock()
	defer mu.RUnlock()
	return dslCache
}
