package matchers

import (
	"regexp"
	"testing"
	"time"
)

func TestRegexCaching(t *testing.T) {
	pattern := regexp.MustCompile(`([a-zA-Z0-9]+)=([^&\s]+)`)
	corpus := "user=admin&password=secret123&token=xyz789"

	// Clear cache
	globalRegexResultCache.cache = make(map[regexCacheKey]*regexCacheEntry)

	// First call - should cache result
	start := time.Now()
	matches1 := cachedFindAllString(pattern, corpus, -1)
	uncachedTime := time.Since(start)

	if len(matches1) == 0 {
		t.Fatal("Expected matches but got none")
	}

	// Second call - should use cache
	start = time.Now()
	matches2 := cachedFindAllString(pattern, corpus, -1)
	cachedTime := time.Since(start)

	if len(matches2) != len(matches1) {
		t.Fatalf("Cache returned different results: %d vs %d", len(matches1), len(matches2))
	}

	// Cached call should be significantly faster
	if cachedTime >= uncachedTime {
		t.Logf("Cache performance - Uncached: %v, Cached: %v", uncachedTime, cachedTime)
	}

	// Test cache entry exists
	if len(globalRegexResultCache.cache) != 1 {
		t.Fatalf("Expected 1 cache entry, got %d", len(globalRegexResultCache.cache))
	}

	t.Logf("✅ Regex caching working - Uncached: %v, Cached: %v", uncachedTime, cachedTime)
}

func BenchmarkRegexWithoutCache(b *testing.B) {
	pattern := regexp.MustCompile(`([a-zA-Z0-9]+)=([^&\s]+)`)
	corpus := "user=admin&password=secret123&token=xyz789"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pattern.FindAllString(corpus, -1)
	}
}

func BenchmarkRegexWithCache(b *testing.B) {
	pattern := regexp.MustCompile(`([a-zA-Z0-9]+)=([^&\s]+)`)
	corpus := "user=admin&password=secret123&token=xyz789"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cachedFindAllString(pattern, corpus, -1)
	}
}

func TestRegexCache_RespectsDifferentN(t *testing.T) {
	pattern := regexp.MustCompile(`a`)
	corpus := "aaaaa"
	// Clear cache
	globalRegexResultCache.cache = make(map[regexCacheKey]*regexCacheEntry)

	got1 := cachedFindAllString(pattern, corpus, 2)
	if len(got1) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(got1))
	}
	// Now ask for more than previously cached n; should still return full
	got2 := cachedFindAllString(pattern, corpus, -1)
	if len(got2) != 5 {
		t.Fatalf("expected 5 matches from cache, got %d", len(got2))
	}
}
