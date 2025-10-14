package templates

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCache(t *testing.T) {
	templates := NewCache()
	testErr := errors.New("test error")

	data, _, err := templates.Has("test")
	require.Nil(t, err, "invalid value for err")
	require.Nil(t, data, "invalid value for data")

	item := &Template{}

	templates.Store("test", item, nil, testErr)
	data, _, err = templates.Has("test")
	require.Equal(t, testErr, err, "invalid value for err")
	require.Equal(t, item, data, "invalid value for data")
}

func TestCacheFileBased(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cache_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	cache := NewCache()
	template := &Template{}

	// Create a test file
	testFile := filepath.Join(tempDir, "test.yaml")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	// Store template with file
	cache.Store(testFile, template, []byte("raw content"), nil)

	// Should be able to retrieve it
	retrieved, raw, err := cache.Has(testFile)
	require.NoError(t, err)
	require.Equal(t, template, retrieved)
	require.Equal(t, []byte("raw content"), raw)

	// Modify file content (should invalidate cache)
	time.Sleep(10 * time.Millisecond) // Ensure mod time difference
	err = os.WriteFile(testFile, []byte("modified content"), 0644)
	require.NoError(t, err)

	// Cache should be invalidated
	retrieved, raw, err = cache.Has(testFile)
	require.NoError(t, err)
	require.Nil(t, retrieved)
	require.Nil(t, raw)
}

func TestCacheFileDeletion(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cache_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	cache := NewCache()
	template := &Template{}

	// Create a test file
	testFile := filepath.Join(tempDir, "test.yaml")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	// Store template with file
	cache.Store(testFile, template, []byte("raw content"), nil)

	// Should be able to retrieve it
	retrieved, raw, err := cache.Has(testFile)
	require.NoError(t, err)
	require.Equal(t, template, retrieved)
	require.Equal(t, []byte("raw content"), raw)

	// Delete the file
	err = os.Remove(testFile)
	require.NoError(t, err)

	// Cache should be invalidated
	retrieved, raw, err = cache.Has(testFile)
	require.NoError(t, err)
	require.Nil(t, retrieved)
	require.Nil(t, raw)
}

func TestCacheStoreWithoutRaw(t *testing.T) {
	cache := NewCache()
	template := &Template{}
	testErr := errors.New("test error")

	// Store without raw data
	cache.StoreWithoutRaw("test", template, testErr)

	// Should be able to retrieve template but not raw data
	retrieved, raw, err := cache.Has("test")
	require.Equal(t, testErr, err)
	require.Equal(t, template, retrieved)
	require.Empty(t, raw)
}

func TestCacheGet(t *testing.T) {
	cache := NewCache()
	template := &Template{}
	testErr := errors.New("test error")

	// Test cache miss
	retrieved, err := cache.Get("nonexistent")
	require.NoError(t, err)
	require.Nil(t, retrieved)

	// Store template
	cache.Store("test", template, []byte("raw"), testErr)

	// Should be able to get template
	retrieved, err = cache.Get("test")
	require.Equal(t, testErr, err)
	require.Equal(t, template, retrieved)
}

func TestCachePurge(t *testing.T) {
	cache := NewCache()
	template := &Template{}

	// Store multiple templates
	cache.Store("test1", template, []byte("raw1"), nil)
	cache.Store("test2", template, []byte("raw2"), nil)

	// Verify they exist
	retrieved1, _, _ := cache.Has("test1")
	require.Equal(t, template, retrieved1)
	retrieved2, _, _ := cache.Has("test2")
	require.Equal(t, template, retrieved2)

	// Purge cache
	cache.Purge()

	// Should be empty now
	retrieved1, _, _ = cache.Has("test1")
	require.Nil(t, retrieved1)
	retrieved2, _, _ = cache.Has("test2")
	require.Nil(t, retrieved2)
}

func TestCacheNonFileTemplates(t *testing.T) {
	cache := NewCache()
	template := &Template{}
	testErr := errors.New("test error")

	// Store non-file template (like the original test)
	cache.Store("nonfile", template, []byte("raw"), testErr)

	// Should work normally
	retrieved, raw, err := cache.Has("nonfile")
	require.Equal(t, testErr, err)
	require.Equal(t, template, retrieved)
	require.Equal(t, []byte("raw"), raw)
}

func TestCacheFileBasedStoreWithoutRaw(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "cache_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	cache := NewCache()
	template := &Template{}

	// Create a test file
	testFile := filepath.Join(tempDir, "test.yaml")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	require.NoError(t, err)

	// Store template without raw data
	cache.StoreWithoutRaw(testFile, template, nil)

	// Should be able to retrieve template but not raw data
	retrieved, raw, err := cache.Has(testFile)
	require.NoError(t, err)
	require.Equal(t, template, retrieved)
	require.Empty(t, raw)
}
