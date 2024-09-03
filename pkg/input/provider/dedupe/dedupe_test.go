package dedupe

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFuzzingDeduper(t *testing.T) {
	t.Run("Basic URL Deduplication", func(t *testing.T) {
		tests := []struct {
			name     string
			urls     []string
			expected []bool
		}{
			{
				name:     "Simple unique URLs",
				urls:     []string{"http://example.com/page1", "http://example.com/page2"},
				expected: []bool{true, true},
			},
			{
				name:     "Duplicate URLs",
				urls:     []string{"http://example.com/page1", "http://example.com/page1"},
				expected: []bool{true, false},
			},
			{
				name:     "URLs with different query param values",
				urls:     []string{"http://example.com/page?id=1", "http://example.com/page?id=2"},
				expected: []bool{true, false},
			},
			{
				name:     "URLs with different query param orders",
				urls:     []string{"http://example.com/page?a=1&b=2", "http://example.com/page?b=2&a=1"},
				expected: []bool{true, false},
			},
			{
				name:     "URLs with and without trailing slash",
				urls:     []string{"http://example.com/page/", "http://example.com/page"},
				expected: []bool{true, true},
			},
			{
				name:     "URLs with different schemes",
				urls:     []string{"http://example.com", "https://example.com"},
				expected: []bool{true, true},
			},
			{
				name:     "URLs with query params and without",
				urls:     []string{"http://example.com/page", "http://example.com/page?param=value"},
				expected: []bool{true, true},
			},
			{
				name:     "Invalid URLs",
				urls:     []string{"http://example.com/page", "not a valid url"},
				expected: []bool{true, false},
			},
			{
				name:     "URLs with empty query params",
				urls:     []string{"http://example.com/page?param1=&param2=", "http://example.com/page?param2=&param1="},
				expected: []bool{true, false},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				deduper := NewFuzzingDeduper()
				for i, url := range tt.urls {
					result := deduper.Add(url)
					require.Equal(t, tt.expected[i], result, "Add(%q) = %v, want %v", url, result, tt.expected[i])
				}
			})
		}
	})

	t.Run("Large Set Deduplication", func(t *testing.T) {
		deduper := NewFuzzingDeduper()
		baseURL := "http://example.com/page?id=%d&param=%s"

		for i := 0; i < 1000; i++ {
			url := fmt.Sprintf(baseURL, i, "value")
			result := deduper.Add(url)
			if i == 0 {
				require.True(t, result, "First URL should be added")
			} else {
				require.False(t, result, "Duplicate URL pattern should not be added: %s", url)
			}
		}

		allItems := deduper.items.GetAll()
		require.Len(t, allItems, 1, "Expected 1 unique URL pattern, got %d", len(allItems))
	})

	t.Run("Path Parameters", func(t *testing.T) {
		deduper := NewFuzzingDeduper()

		require.True(t, deduper.Add("https://example.com/page/1337"))
		require.False(t, deduper.Add("https://example.com/page/1332"))
	})

	t.Run("TestPHP Vulnweb URLs", func(t *testing.T) {
		urls := []string{
			"http://testphp.vulnweb.com/hpp/?pp=12",
			"http://testphp.vulnweb.com/hpp/params.php?p=valid&pp=12",
			"http://testphp.vulnweb.com/artists.php?artist=3",
			"http://testphp.vulnweb.com/artists.php?artist=1",
			"http://testphp.vulnweb.com/artists.php?artist=2",
			"http://testphp.vulnweb.com/listproducts.php?artist=3",
			"http://testphp.vulnweb.com/listproducts.php?cat=4",
			"http://testphp.vulnweb.com/listproducts.php?cat=3",
			"http://testphp.vulnweb.com/listproducts.php?cat=2",
			"http://testphp.vulnweb.com/listproducts.php?artist=2",
			"http://testphp.vulnweb.com/listproducts.php?artist=1",
			"http://testphp.vulnweb.com/listproducts.php?cat=1",
			"http://testphp.vulnweb.com/showimage.php?file=./pictures/6.jpg",
			"http://testphp.vulnweb.com/product.php?pic=6",
			"http://testphp.vulnweb.com/showimage.php?file=./pictures/6.jpg&size=160",
		}

		expectedUnique := 8

		deduper := NewFuzzingDeduper()
		uniqueCount := 0

		for _, url := range urls {
			if deduper.Add(url) {
				uniqueCount++
			}
		}

		require.Equal(t, expectedUnique, uniqueCount, "Expected %d unique URLs, but got %d", expectedUnique, uniqueCount)

		// Test for duplicates
		for _, url := range urls {
			require.False(t, deduper.Add(url), "URL should have been identified as duplicate: %s", url)
		}
	})
}
