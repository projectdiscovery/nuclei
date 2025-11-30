package index

import (
	"encoding/gob"
	"maps"
	"os"
	"path/filepath"
	"sync"

	"github.com/maypok86/otter/v2"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	folderutil "github.com/projectdiscovery/utils/folder"
)

const (
	// IndexFileName is the name of the persistent cache file.
	IndexFileName = "index.gob"

	// IndexVersion is the schema version for cache invalidation on breaking
	// changes.
	IndexVersion = 1

	// DefaultMaxSize is the default maximum number of templates to cache.
	DefaultMaxSize = 50000

	// DefaultMaxWeight is the default maximum weight of the cache.
	DefaultMaxWeight = DefaultMaxSize * 800 // ~40MB assuming ~800B/entry
)

// Index represents a cache for template metadata.
type Index struct {
	cache     *otter.Cache[string, *Metadata]
	cacheFile string
	mu        sync.RWMutex
	version   int
}

// cacheSnapshot represents the serialized cache structure.
type cacheSnapshot struct {
	Version int                  `gob:"version"`
	Data    map[string]*Metadata `gob:"data"`
}

// NewIndex creates a new template metadata cache with the given options.
func NewIndex(cacheDir string) (*Index, error) {
	if cacheDir == "" {
		cacheDir = folderutil.AppCacheDirOrDefault(".nuclei-cache", config.BinaryName)
	}

	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, err
	}

	cacheFile := filepath.Join(cacheDir, IndexFileName)

	// NOTE(dwisiswant0): Build cache with adaptive sizing based on memory cost.
	opts := &otter.Options[string, *Metadata]{
		MaximumWeight: uint64(DefaultMaxWeight),
		Weigher: func(key string, value *Metadata) uint32 {
			if value == nil {
				return uint32(len(key))
			}

			weight := len(key)
			weight += len(value.ID)
			weight += len(value.FilePath)
			weight += 24 // ModTime is time.Time (24B)
			weight += len(value.Name)
			weight += len(value.Severity)
			weight += len(value.ProtocolType)
			weight += len(value.TemplateVerifier)

			for _, author := range value.Authors {
				weight += len(author)
			}
			for _, tag := range value.Tags {
				weight += len(tag)
			}

			return uint32(weight)
		},
	}

	cache, err := otter.New(opts)
	if err != nil {
		return nil, err
	}

	c := &Index{
		cache:     cache,
		cacheFile: cacheFile,
		version:   IndexVersion,
	}

	return c, nil
}

// NewDefaultIndex creates a index with default settings in the default cache
// directory.
func NewDefaultIndex() (*Index, error) {
	return NewIndex("")
}

// Get retrieves metadata for a template path, validating freshness via mtime.
func (i *Index) Get(path string) (*Metadata, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()

	metadata, found := i.cache.GetIfPresent(path)
	if !found {
		return nil, false
	}

	if !metadata.IsValid() {
		go i.Delete(path)

		return nil, false
	}

	return metadata, true
}

// Set stores metadata for a template path.
//
// The caller is responsible for ensuring the metadata is valid and contains
// the correct checksum before calling this method.
// Use [SetFromTemplate] for automatic extraction and checksum computation.
//
// Returns the metadata and whether it was successfully cached (false if evicted).
func (i *Index) Set(path string, metadata *Metadata) (*Metadata, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()

	return i.cache.Set(path, metadata)
}

// SetFromTemplate extracts metadata from a parsed template and stores it.
//
// Returns the metadata and whether it was successfully cached. The metadata is
// always returned (even on checksum failure) for immediate filtering use.
// Returns false if checksum computation fails or cache eviction occurs.
func (i *Index) SetFromTemplate(path string, tpl *templates.Template) (*Metadata, bool) {
	metadata := &Metadata{
		ID:       tpl.ID,
		FilePath: path,

		Name:     tpl.Info.Name,
		Authors:  tpl.Info.Authors.ToSlice(),
		Tags:     tpl.Info.Tags.ToSlice(),
		Severity: tpl.Info.SeverityHolder.Severity.String(),

		ProtocolType: tpl.Type().String(),

		Verified:         tpl.Verified,
		TemplateVerifier: tpl.TemplateVerifier,
	}

	info, err := os.Stat(path)
	if err != nil {
		return metadata, false
	}
	metadata.ModTime = info.ModTime()

	return i.Set(path, metadata)
}

// Has checks if metadata exists for a path without validation.
func (i *Index) Has(path string) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()

	_, found := i.cache.GetIfPresent(path)

	return found
}

// Delete removes metadata for a path.
func (i *Index) Delete(path string) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.cache.Invalidate(path)
}

// Size returns the number of cached entries.
func (i *Index) Size() int {
	i.mu.RLock()
	defer i.mu.RUnlock()

	return i.cache.EstimatedSize()
}

// Clear removes all cached entries.
func (i *Index) Clear() {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.cache.InvalidateAll()
}

// Save persists the cache to disk using gob encoding.
func (i *Index) Save() error {
	i.mu.RLock()
	defer i.mu.RUnlock()

	snapshot := &cacheSnapshot{
		Version: i.version,
		Data:    make(map[string]*Metadata),
	}

	maps.Insert(snapshot.Data, i.cache.All())

	// NOTE(dwisiswant0): write to temp for atomic op.
	tmpFile := i.cacheFile + ".tmp"
	file, err := os.Create(tmpFile)
	if err != nil {
		return err
	}

	encoder := gob.NewEncoder(file)
	if err := encoder.Encode(snapshot); err != nil {
		_ = file.Close()
		_ = os.Remove(tmpFile)

		return err
	}

	if err := file.Close(); err != nil {
		_ = os.Remove(tmpFile)

		return err
	}

	if err := os.Rename(tmpFile, i.cacheFile); err != nil {
		_ = os.Remove(tmpFile)

		return err
	}

	return nil
}

// Load loads the cache from disk using gob decoding.
func (i *Index) Load() error {
	file, err := os.Open(i.cacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return err
	}
	defer func() { _ = file.Close() }()

	var snapshot cacheSnapshot

	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&snapshot); err != nil {
		_ = file.Close()
		_ = os.Remove(i.cacheFile)

		return nil
	}

	if snapshot.Version != i.version {
		_ = file.Close()
		_ = os.Remove(i.cacheFile)

		return nil
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	for key, value := range snapshot.Data {
		i.cache.Set(key, value)
	}

	return nil
}

// Filter returns all template paths that match the given filter criteria.
func (i *Index) Filter(filter *Filter) []string {
	if filter == nil || filter.IsEmpty() {
		return i.All()
	}

	i.mu.RLock()
	defer i.mu.RUnlock()

	var matched []string
	for path, metadata := range i.cache.All() {
		if filter.Matches(metadata) {
			matched = append(matched, path)
		}
	}

	return matched
}

// FilterFunc returns all template paths that match the given filter function.
func (i *Index) FilterFunc(fn FilterFunc) []string {
	if fn == nil {
		return i.All()
	}

	i.mu.RLock()
	defer i.mu.RUnlock()

	var matched []string
	for path, metadata := range i.cache.All() {
		if fn(metadata) {
			matched = append(matched, path)
		}
	}

	return matched
}

// All returns all template paths in the index.
func (i *Index) All() []string {
	i.mu.RLock()
	defer i.mu.RUnlock()

	paths := make([]string, 0, i.cache.EstimatedSize())
	for path := range i.cache.All() {
		paths = append(paths, path)
	}

	return paths
}

// GetAll returns all metadata entries in the index.
func (i *Index) GetAll() map[string]*Metadata {
	i.mu.RLock()
	defer i.mu.RUnlock()

	result := maps.Collect(i.cache.All())

	return result
}

// Count returns the number of templates matching the filter.
func (i *Index) Count(filter *Filter) int {
	if filter == nil || filter.IsEmpty() {
		return i.Size()
	}

	i.mu.RLock()
	defer i.mu.RUnlock()

	count := 0
	for _, metadata := range i.cache.All() {
		if filter.Matches(metadata) {
			count++
		}
	}

	return count
}
