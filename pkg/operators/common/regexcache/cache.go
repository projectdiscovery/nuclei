package regexcache

import (
	"regexp"
	"sync"
)

// Global regex cache to avoid recompiling same patterns
var (
	regexCache     = make(map[string]*regexp.Regexp)
	regexCacheLock sync.RWMutex
)

// GetCompiledRegex returns a cached compiled regex or creates new one
func GetCompiledRegex(pattern string) (*regexp.Regexp, error) {
	regexCacheLock.RLock()
	if compiled, exists := regexCache[pattern]; exists {
		regexCacheLock.RUnlock()
		return compiled, nil
	}
	regexCacheLock.RUnlock()

	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	regexCacheLock.Lock()
	regexCache[pattern] = compiled
	regexCacheLock.Unlock()

	return compiled, nil
}

// ClearCache clears the regex cache
func ClearCache() {
	regexCacheLock.Lock()
	regexCache = make(map[string]*regexp.Regexp)
	regexCacheLock.Unlock()
}

// GetCacheSize returns the number of cached regexes
func GetCacheSize() int {
	regexCacheLock.RLock()
	defer regexCacheLock.RUnlock()
	return len(regexCache)
}
