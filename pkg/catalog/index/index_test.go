package index

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/code"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/headless"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/stretchr/testify/require"
)

func TestNewIndex(t *testing.T) {
	t.Run("with custom directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		cache, err := NewIndex(tmpDir)
		require.NoError(t, err, "Failed to create cache with custom directory")
		require.NotNil(t, cache, "Cache should not be nil")
		require.Equal(t, filepath.Join(tmpDir, IndexFileName), cache.cacheFile)
		require.Equal(t, IndexVersion, cache.version)
	})

	t.Run("with default directory", func(t *testing.T) {
		cache, err := NewDefaultIndex()
		require.NoError(t, err, "Failed to create cache with default directory")
		require.NotNil(t, cache, "Cache should not be nil")
	})
}

func TestCacheBasicOperations(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewIndex(tmpDir)
	require.NoError(t, err)

	metadata := &Metadata{
		ID:       "concurrent-test",
		FilePath: "/tmp/concurrent.yaml",
	}

	t.Run("Set and Has", func(t *testing.T) {
		cache.Set(metadata.FilePath, metadata)
		require.Equal(t, 1, cache.Size(), "Cache size should be 1 after Set")
		require.True(t, cache.Has(metadata.FilePath), "Cache should contain the path after Set")
		require.False(t, cache.Has("/nonexistent"), "Cache should not contain nonexistent path")
	})

	t.Run("Get with validation", func(t *testing.T) {
		// Get should fail validation for nonexistent file
		retrieved, found := cache.Get(metadata.FilePath)
		require.False(t, found, "Get should fail validation for nonexistent file")
		require.Nil(t, retrieved, "Retrieved metadata should be nil for invalid entry")
	})

	t.Run("Delete", func(t *testing.T) {
		cache.Set(metadata.FilePath, metadata)
		require.True(t, cache.Has(metadata.FilePath), "Cache should contain path before Delete")

		cache.Delete(metadata.FilePath)
		require.False(t, cache.Has(metadata.FilePath), "Cache should not contain path after Delete")
	})

	t.Run("Clear", func(t *testing.T) {
		cache.Set(metadata.FilePath, metadata)
		cache.Set("/tmp/test2.yaml", &Metadata{ID: "test2", FilePath: "/tmp/test2.yaml"})
		require.True(t, cache.Size() > 0, "Cache should have entries before Clear")

		cache.Clear()
		require.Equal(t, 0, cache.Size(), "Cache should be empty after Clear")
	})
}

func TestCachePersistence(t *testing.T) {
	tmpDir := t.TempDir()

	metadata1 := &Metadata{
		ID:           "persist-test-1",
		FilePath:     "/tmp/persist1.yaml",
		Name:         "Persistence Test 1",
		Authors:      []string{"tester"},
		Tags:         []string{"test"},
		Severity:     "medium",
		ProtocolType: "dns",
	}

	metadata2 := &Metadata{
		ID:           "persist-test-2",
		FilePath:     "/tmp/persist2.yaml",
		Name:         "Persistence Test 2",
		Authors:      []string{"tester2"},
		Tags:         []string{"cve"},
		Severity:     "critical",
		ProtocolType: "http",
	}

	t.Run("Save and Load", func(t *testing.T) {
		// Create cache and add entries
		cache1, err := NewIndex(tmpDir)
		require.NoError(t, err)

		cache1.Set(metadata1.FilePath, metadata1)
		cache1.Set(metadata2.FilePath, metadata2)
		require.Equal(t, 2, cache1.Size())

		// Save to disk
		err = cache1.Save()
		require.NoError(t, err, "Failed to save cache")

		// Verify cache file exists
		cacheFile := filepath.Join(tmpDir, IndexFileName)
		stat, err := os.Stat(cacheFile)
		require.NoError(t, err, "Cache file should exist")
		require.Greater(t, stat.Size(), int64(0), "Cache file should not be empty")

		// Create new cache and load
		cache2, err := NewIndex(tmpDir)
		require.NoError(t, err)
		require.Equal(t, 0, cache2.Size(), "New cache should be empty before Load")

		err = cache2.Load()
		require.NoError(t, err, "Failed to load cache")

		// Verify data was loaded
		require.Equal(t, 2, cache2.Size(), "Loaded cache should have 2 entries")
		require.True(t, cache2.Has(metadata1.FilePath), "Loaded cache should contain first entry")
		require.True(t, cache2.Has(metadata2.FilePath), "Loaded cache should contain second entry")
	})

	t.Run("Load non-existent cache", func(t *testing.T) {
		emptyDir := t.TempDir()
		cache, err := NewIndex(emptyDir)
		require.NoError(t, err)

		// Loading non-existent cache should not error
		err = cache.Load()
		require.NoError(t, err, "Loading non-existent cache should not error")
		require.Equal(t, 0, cache.Size(), "Cache should be empty after loading non-existent file")
	})

	t.Run("Atomic save", func(t *testing.T) {
		cache, err := NewIndex(tmpDir)
		require.NoError(t, err)

		cache.Set(metadata1.FilePath, metadata1)
		err = cache.Save()
		require.NoError(t, err)

		// Verify no .tmp file left behind
		tmpFile := filepath.Join(tmpDir, IndexFileName+".tmp")
		_, err = os.Stat(tmpFile)
		require.True(t, os.IsNotExist(err), "Temporary file should not exist after save")

		// Verify actual cache file exists
		cacheFile := filepath.Join(tmpDir, IndexFileName)
		_, err = os.Stat(cacheFile)
		require.NoError(t, err, "Cache file should exist")
	})
}

func TestIndexVersionMismatch(t *testing.T) {
	tmpDir := t.TempDir()

	// Create cache with current version
	cache1, err := NewIndex(tmpDir)
	require.NoError(t, err)

	metadata := &Metadata{
		ID:       "version-test",
		FilePath: "/tmp/version.yaml",
	}
	cache1.Set(metadata.FilePath, metadata)

	// Save with current version
	err = cache1.Save()
	require.NoError(t, err)

	// Manually modify version and save again
	cache1.version = 999
	err = cache1.Save()
	require.NoError(t, err)

	// Try to load with different version
	cache2, err := NewIndex(tmpDir)
	require.NoError(t, err)

	// Load should succeed but cache should be empty (version mismatch)
	err = cache2.Load()
	require.NoError(t, err, "Load should not error on version mismatch")
	require.Equal(t, 0, cache2.Size(), "Cache should be empty after version mismatch")
}

func TestCacheCorruptedFile(t *testing.T) {
	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, IndexFileName)

	// Create corrupted cache file
	err := os.WriteFile(cacheFile, []byte("corrupted data that is not valid gob"), 0644)
	require.NoError(t, err)

	// Try to load corrupted cache
	cache, err := NewIndex(tmpDir)
	require.NoError(t, err)

	err = cache.Load()
	require.NoError(t, err, "Load should not error on corrupted cache")
	require.Equal(t, 0, cache.Size(), "Cache should be empty after loading corrupted file")

	// Corrupted file should be removed
	_, err = os.Stat(cacheFile)
	require.True(t, os.IsNotExist(err), "Corrupted cache file should be removed")
}

func TestMetadataValidation(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.yaml")

	t.Run("Valid metadata", func(t *testing.T) {
		// Create a test file
		err := os.WriteFile(tmpFile, []byte("id: test\ninfo:\n  name: Test"), 0644)
		require.NoError(t, err)

		info, err := os.Stat(tmpFile)
		require.NoError(t, err)

		// Create metadata with correct checksum
		metadata := &Metadata{
			ID:       "test",
			FilePath: tmpFile,
			ModTime:  info.ModTime(),
		}

		// Should be valid
		require.True(t, metadata.IsValid(), "Metadata should be valid for unchanged file")
	})

	t.Run("Invalid metadata after file modification", func(t *testing.T) {
		// Create the test file first to ensure it exists in this subtest
		err := os.WriteFile(tmpFile, []byte("id: test\ninfo:\n  name: Test"), 0644)
		require.NoError(t, err)

		// Set file ModTime to past to ensure modification is detectable
		oldTime := time.Now().Add(-2 * time.Second)
		err = os.Chtimes(tmpFile, oldTime, oldTime)
		require.NoError(t, err)

		info, err := os.Stat(tmpFile)
		require.NoError(t, err)

		metadata := &Metadata{
			ID:       "test",
			FilePath: tmpFile,
			ModTime:  info.ModTime(),
		}

		// Modify file
		err = os.WriteFile(tmpFile, []byte("id: test\ninfo:\n  name: Modified"), 0644)
		require.NoError(t, err)

		// Should now be invalid
		require.False(t, metadata.IsValid(), "Metadata should be invalid after file modification")
	})

	t.Run("Invalid metadata for deleted file", func(t *testing.T) {
		// Create the test file first to ensure it exists in this subtest
		err := os.WriteFile(tmpFile, []byte("id: test\ninfo:\n  name: Test"), 0644)
		require.NoError(t, err)

		info, err := os.Stat(tmpFile)
		require.NoError(t, err)

		metadata := &Metadata{
			ID:       "test",
			FilePath: tmpFile,
			ModTime:  info.ModTime(),
		}

		// Delete file
		err = os.Remove(tmpFile)
		require.NoError(t, err)

		// Should be invalid
		require.False(t, metadata.IsValid(), "Metadata should be invalid for deleted file")
	})
}

func TestSetFromTemplate(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "extract.yaml")

	// Create a test file
	err := os.WriteFile(tmpFile, []byte("id: extract-test"), 0644)
	require.NoError(t, err)

	cache, err := NewIndex(tmpDir)
	require.NoError(t, err)

	t.Run("Basic metadata extraction", func(t *testing.T) {
		template := &templates.Template{
			ID: "extract-test",
			Info: model.Info{
				Name:        "Extract Test Template",
				Authors:     stringslice.StringSlice{Value: "author1,author2"},
				Tags:        stringslice.StringSlice{Value: "tag1,tag2"},
				Description: "Test description",
				SeverityHolder: severity.Holder{
					Severity: severity.High,
				},
			},
			SelfContained:    true,
			Verified:         true,
			TemplateVerifier: "test-verifier",
		}

		metadata, ok := cache.SetFromTemplate(tmpFile, template)
		require.True(t, ok, "Failed to set metadata from template")
		require.NotNil(t, metadata, "Metadata should not be nil")

		// Verify core fields
		require.Equal(t, "extract-test", metadata.ID)
		require.Equal(t, tmpFile, metadata.FilePath)

		// Verify Info fields
		require.Equal(t, "Extract Test Template", metadata.Name)
		require.Equal(t, []string{"author1,author2"}, metadata.Authors)
		require.Equal(t, []string{"tag1,tag2"}, metadata.Tags)
		require.Equal(t, "high", metadata.Severity)

		// Verify flags
		require.True(t, metadata.Verified)
		require.Equal(t, "test-verifier", metadata.TemplateVerifier)
	})

	t.Run("HTTP protocol detection", func(t *testing.T) {
		// Create a separate test file for this test
		httpFile := filepath.Join(tmpDir, "http-test.yaml")
		err := os.WriteFile(httpFile, []byte("id: http-test"), 0644)
		require.NoError(t, err)

		template := &templates.Template{
			ID: "http-test",
			Info: model.Info{
				Name:    "HTTP Test",
				Authors: stringslice.StringSlice{Value: "tester"},
				SeverityHolder: severity.Holder{
					Severity: severity.Medium,
				},
			},
			RequestsHTTP: []*http.Request{{Method: http.HTTPMethodTypeHolder{MethodType: http.HTTPGet}}},
		}

		metadata, ok := cache.SetFromTemplate(httpFile, template)
		require.True(t, ok)
		require.NotNil(t, metadata)
		require.Equal(t, "http", metadata.ProtocolType)
	})

	t.Run("Extract with missing file", func(t *testing.T) {
		template := &templates.Template{
			ID: "missing-test",
			Info: model.Info{
				Name:    "Missing File Test",
				Authors: stringslice.StringSlice{Value: "tester"},
				SeverityHolder: severity.Holder{
					Severity: severity.Low,
				},
			},
		}

		metadata, ok := cache.SetFromTemplate("/nonexistent/file.yaml", template)
		require.False(t, ok, "Should return false for nonexistent file")
		require.NotNil(t, metadata, "Metadata should still be returned")
	})
}

func TestMetadataMatchingHelpers(t *testing.T) {
	metadata := &Metadata{
		Tags:         []string{"cve", "rce", "apache"},
		Authors:      []string{"pdteam", "geeknik"},
		Severity:     "critical",
		ProtocolType: "http",
	}

	t.Run("HasTag", func(t *testing.T) {
		require.True(t, metadata.HasTag("cve"))
		require.True(t, metadata.HasTag("rce"))
		require.True(t, metadata.HasTag("apache"))
		require.False(t, metadata.HasTag("xxe"))
		require.False(t, metadata.HasTag(""))
	})

	t.Run("HasAuthor", func(t *testing.T) {
		require.True(t, metadata.HasAuthor("pdteam"))
		require.True(t, metadata.HasAuthor("geeknik"))
		require.False(t, metadata.HasAuthor("unknown"))
		require.False(t, metadata.HasAuthor(""))
	})

	t.Run("MatchesSeverity", func(t *testing.T) {
		require.True(t, metadata.MatchesSeverity(severity.Critical))
		require.False(t, metadata.MatchesSeverity(severity.High))
		require.False(t, metadata.MatchesSeverity(severity.Medium))
		require.False(t, metadata.MatchesSeverity(severity.Low))
		require.False(t, metadata.MatchesSeverity(severity.Info))
	})

	t.Run("MatchesProtocol", func(t *testing.T) {
		require.True(t, metadata.MatchesProtocol(types.HTTPProtocol))
		require.False(t, metadata.MatchesProtocol(types.DNSProtocol))
		require.False(t, metadata.MatchesProtocol(types.FileProtocol))
		require.False(t, metadata.MatchesProtocol(types.NetworkProtocol))
	})

	t.Run("Empty metadata", func(t *testing.T) {
		emptyMetadata := &Metadata{}
		require.False(t, emptyMetadata.HasTag("any"))
		require.False(t, emptyMetadata.HasAuthor("any"))
	})
}

func TestCacheConcurrency(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewIndex(tmpDir)
	require.NoError(t, err)

	// Test concurrent writes
	t.Run("Concurrent Set", func(t *testing.T) {
		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func(id int) {
				metadata := &Metadata{
					ID:       string(rune('a' + id)),
					FilePath: filepath.Join("/tmp", string(rune('a'+id))+".yaml"),
				}
				cache.Set(metadata.FilePath, metadata)
				done <- true
			}(i)
		}

		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			<-done
		}

		require.Equal(t, 10, cache.Size(), "All concurrent writes should succeed")
	})

	// Test concurrent reads
	t.Run("Concurrent Has", func(t *testing.T) {
		metadata := &Metadata{
			ID:       "concurrent-test",
			FilePath: "/tmp/concurrent.yaml",
		}
		cache.Set(metadata.FilePath, metadata)

		done := make(chan bool)
		for i := 0; i < 20; i++ {
			go func() {
				_ = cache.Has(metadata.FilePath)
				done <- true
			}()
		}

		// Wait for all goroutines
		for i := 0; i < 20; i++ {
			<-done
		}
	})
}

func TestCacheSize(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewIndex(tmpDir)
	require.NoError(t, err)

	require.Equal(t, 0, cache.Size(), "New cache should have size 0")

	// Add entries
	for i := 0; i < 5; i++ {
		metadata := &Metadata{
			ID:       string(rune('a' + i)),
			FilePath: filepath.Join("/tmp", string(rune('a'+i))+".yaml"),
		}
		cache.Set(metadata.FilePath, metadata)
	}

	require.Equal(t, 5, cache.Size(), "Cache should have size 5 after adding 5 entries")

	// Delete entries
	cache.Delete("/tmp/a.yaml")
	cache.Delete("/tmp/b.yaml")

	require.Equal(t, 3, cache.Size(), "Cache should have size 3 after deleting 2 entries")

	// Clear cache
	cache.Clear()
	require.Equal(t, 0, cache.Size(), "Cache should have size 0 after Clear")
}

func TestCacheGetWithValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewIndex(tmpDir)
	require.NoError(t, err)

	// Create a real file for testing validation
	tmpFile := filepath.Join(tmpDir, "test.yaml")
	err = os.WriteFile(tmpFile, []byte("id: test"), 0644)
	require.NoError(t, err)

	info, err := os.Stat(tmpFile)
	require.NoError(t, err)

	metadata := &Metadata{
		ID:       "test",
		FilePath: tmpFile,
		ModTime:  info.ModTime(),
		Name:     "Test Template",
	}

	// Set and get should work with valid file
	cache.Set(metadata.FilePath, metadata)
	retrieved, found := cache.Get(metadata.FilePath)
	require.True(t, found, "Should find entry with valid file")
	require.NotNil(t, retrieved, "Retrieved metadata should not be nil")
	require.Equal(t, metadata.ID, retrieved.ID)
}

func TestCacheSaveErrorHandling(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewIndex(tmpDir)
	require.NoError(t, err)

	metadata := &Metadata{
		ID:       "test",
		FilePath: "/tmp/test.yaml",
	}
	cache.Set(metadata.FilePath, metadata)

	// Make cache directory read-only to force save error
	err = os.Chmod(tmpDir, 0444)
	require.NoError(t, err)
	defer func() { _ = os.Chmod(tmpDir, 0755) }() // Restore permissions

	err = cache.Save()
	require.Error(t, err, "Save should fail with read-only directory")
}

func TestNewCacheWithInvalidDirectory(t *testing.T) {
	// Try to create cache in a file path (should fail)
	tmpFile := filepath.Join(t.TempDir(), "file.txt")
	err := os.WriteFile(tmpFile, []byte("test"), 0644)
	require.NoError(t, err)

	cache, err := NewIndex(tmpFile)
	require.Error(t, err, "NewCache should fail when path is a file")
	require.Nil(t, cache, "Cache should be nil on error")
}

func TestCacheLoadCorruptedRemoval(t *testing.T) {
	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, IndexFileName)

	// Create corrupted cache file with invalid gob data
	err := os.WriteFile(cacheFile, []byte("this is not valid gob encoding at all!"), 0644)
	require.NoError(t, err)

	// Verify file exists before Load
	_, err = os.Stat(cacheFile)
	require.NoError(t, err, "Corrupted file should exist")

	// Load should not error but should remove corrupted file
	cache, err := NewIndex(tmpDir)
	require.NoError(t, err)

	err = cache.Load()
	require.NoError(t, err, "Load should not return error for corrupted file")

	// Verify corrupted file was removed
	_, err = os.Stat(cacheFile)
	require.True(t, os.IsNotExist(err), "Corrupted file should be removed")
	require.Equal(t, 0, cache.Size(), "Cache should be empty after loading corrupted file")
}

func TestMetadataExtractionWithNilClassification(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.yaml")
	err := os.WriteFile(tmpFile, []byte("id: test"), 0644)
	require.NoError(t, err)

	template := &templates.Template{
		ID: "nil-classification",
		Info: model.Info{
			Name:    "Template without classification",
			Authors: stringslice.StringSlice{Value: "tester"},
			SeverityHolder: severity.Holder{
				Severity: severity.Medium,
			},
			Classification: nil, // Explicitly nil
		},
	}

	cache, err := NewIndex(tmpDir)
	require.NoError(t, err)

	metadata, ok := cache.SetFromTemplate(tmpFile, template)
	require.True(t, ok)
	require.NotNil(t, metadata)
}

func TestCachePersistenceWithLargeDataset(t *testing.T) {
	tmpDir := t.TempDir()
	cache, err := NewIndex(tmpDir)
	require.NoError(t, err)

	// Add 100 entries to test bulk operations
	for i := 0; i < 100; i++ {
		metadata := &Metadata{
			ID:       fmt.Sprintf("template-%d", i),
			FilePath: filepath.Join("/tmp", fmt.Sprintf("template-%d.yaml", i)),
			Name:     fmt.Sprintf("Template %d", i),
			Authors:  []string{fmt.Sprintf("author%d", i)},
			Tags:     []string{"tag1", "tag2", "tag3"},
			Severity: "high",
		}
		cache.Set(metadata.FilePath, metadata)
	}

	require.Equal(t, 100, cache.Size(), "Cache should contain 100 entries")

	// Save to disk
	err = cache.Save()
	require.NoError(t, err)

	// Load into new cache
	cache2, err := NewIndex(tmpDir)
	require.NoError(t, err)
	err = cache2.Load()
	require.NoError(t, err)

	require.Equal(t, 100, cache2.Size(), "Loaded cache should contain 100 entries")

	// Verify a sample entry
	found := cache2.Has("/tmp/template-50.yaml")
	require.True(t, found, "Should find sample entry")
}

func TestMetadataHelperMethods(t *testing.T) {
	metadata := &Metadata{
		ID:           "helper-test",
		Tags:         []string{},
		Authors:      []string{},
		Severity:     "",
		ProtocolType: "",
	}

	t.Run("Empty tags", func(t *testing.T) {
		require.False(t, metadata.HasTag("anytag"))
	})

	t.Run("Empty authors", func(t *testing.T) {
		require.False(t, metadata.HasAuthor("anyauthor"))
	})

	t.Run("Empty severity", func(t *testing.T) {
		require.False(t, metadata.MatchesSeverity(severity.Critical))
	})

	t.Run("Empty protocol", func(t *testing.T) {
		require.False(t, metadata.MatchesProtocol(types.HTTPProtocol))
	})
}

func TestMultipleProtocolsDetection(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "multi.yaml")
	err := os.WriteFile(tmpFile, []byte("id: multi"), 0644)
	require.NoError(t, err)

	// Template with multiple protocol types
	template := &templates.Template{
		ID: "multi-protocol",
		Info: model.Info{
			Name:    "Multi Protocol Template",
			Authors: stringslice.StringSlice{Value: "tester"},
			SeverityHolder: severity.Holder{
				Severity: severity.High,
			},
		},
		RequestsHTTP:     []*http.Request{{Method: http.HTTPMethodTypeHolder{MethodType: http.HTTPGet}}},
		RequestsHeadless: []*headless.Request{{}},
		RequestsCode:     []*code.Request{{}},
	}

	cache, err := NewIndex(tmpDir)
	require.NoError(t, err)

	metadata, ok := cache.SetFromTemplate(tmpFile, template)
	require.True(t, ok)
	require.NotNil(t, metadata)
	require.Equal(t, "http", metadata.ProtocolType, "Primary protocol should be http")
}
