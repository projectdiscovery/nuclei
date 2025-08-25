package matchers

import (
	"regexp"
	"sync"
	"time"
)

type regexCacheKey struct {
	pattern string
	corpus  string
}

type regexCacheEntry struct {
	matches    []string
	submatches [][]string
	timestamp  time.Time
}

type regexResultCache struct {
	cache   map[regexCacheKey]*regexCacheEntry
	mutex   sync.RWMutex
	maxSize int
	ttl     time.Duration
}

var (
	globalRegexResultCache = &regexResultCache{
		cache:   make(map[regexCacheKey]*regexCacheEntry),
		maxSize: 5000,
		ttl:     2 * time.Minute,
	}
)

func (rc *regexResultCache) get(pattern, corpus string) ([]string, [][]string, bool) {
	key := regexCacheKey{pattern: pattern, corpus: corpus}

	rc.mutex.RLock()
	entry, exists := rc.cache[key]
	if exists && time.Since(entry.timestamp) < rc.ttl {
		rc.mutex.RUnlock()
		return entry.matches, entry.submatches, true
	}
	rc.mutex.RUnlock()
	return nil, nil, false
}

func (rc *regexResultCache) set(pattern, corpus string, matches []string, submatches [][]string) {
	key := regexCacheKey{pattern: pattern, corpus: corpus}
	entry := &regexCacheEntry{
		matches:    matches,
		submatches: submatches,
		timestamp:  time.Now(),
	}

	rc.mutex.Lock()
	if len(rc.cache) >= rc.maxSize {
		rc.evictOld()
	}
	rc.cache[key] = entry
	rc.mutex.Unlock()
}

func (rc *regexResultCache) evictOld() {
	now := time.Now()
	for key, entry := range rc.cache {
		if now.Sub(entry.timestamp) > rc.ttl {
			delete(rc.cache, key)
		}
	}

	if len(rc.cache) >= rc.maxSize {
		count := 0
		for key := range rc.cache {
			if count >= rc.maxSize/2 {
				break
			}
			delete(rc.cache, key)
			count++
		}
	}
}

func cachedFindAllString(regex *regexp.Regexp, corpus string, n int) []string {
	if len(corpus) > maxRegexScanBytes {
		return regex.FindAllString(corpus, n)
	}

	pattern := regex.String()

	if cachedMatches, _, found := globalRegexResultCache.get(pattern, corpus); found {
		if n < 0 || len(cachedMatches) <= n {
			return cachedMatches
		}
		return cachedMatches[:n]
	}

	matches := regex.FindAllString(corpus, n)
	globalRegexResultCache.set(pattern, corpus, matches, nil)
	return matches
}

func CachedFindAllStringSubmatch(regex *regexp.Regexp, corpus string, n int) [][]string {
	// Don't cache very large inputs to avoid memory issues
	if len(corpus) > maxRegexScanBytes {
		return regex.FindAllStringSubmatch(corpus, n)
	}

	pattern := regex.String()

	if _, cachedSubmatches, found := globalRegexResultCache.get(pattern, corpus); found && cachedSubmatches != nil {
		if n < 0 || len(cachedSubmatches) <= n {
			return cachedSubmatches
		}
		return cachedSubmatches[:n]
	}

	submatches := regex.FindAllStringSubmatch(corpus, n)
	var matches []string
	for _, submatch := range submatches {
		if len(submatch) > 0 {
			matches = append(matches, submatch[0])
		}
	}
	globalRegexResultCache.set(pattern, corpus, matches, submatches)
	return submatches
}
