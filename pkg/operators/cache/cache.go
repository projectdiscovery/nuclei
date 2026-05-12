package cache

import (
	"regexp"
	"sync"

	"github.com/Knetic/govaluate"
	"github.com/itchyny/gojq"
	"github.com/projectdiscovery/gcache"
)

var (
	initOnce sync.Once
	mu       sync.RWMutex

	regexCap = 4096
	dslCap   = 4096
	jqCap    = 2048

	regexCache gcache.Cache[string, *regexp.Regexp]
	dslCache   gcache.Cache[string, *govaluate.EvaluableExpression]
	jqCache    gcache.Cache[string, *gojq.Code]
)

func initCaches() {
	initOnce.Do(func() {
		regexCache = gcache.New[string, *regexp.Regexp](regexCap).LRU().Build()
		dslCache = gcache.New[string, *govaluate.EvaluableExpression](dslCap).LRU().Build()
		jqCache = gcache.New[string, *gojq.Code](jqCap).LRU().Build()
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

// JQ returns the shared LRU cache for compiled gojq programs. Sharing one
// cache across all extractors means that thousands of templates referencing
// the same JQ query (e.g. `.cves[]`) compile it once.
func JQ() gcache.Cache[string, *gojq.Code] {
	initCaches()
	mu.RLock()
	defer mu.RUnlock()
	return jqCache
}
