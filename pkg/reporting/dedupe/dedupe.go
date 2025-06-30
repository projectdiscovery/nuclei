// Package dedupe implements deduplication layer for nuclei-generated
// issues.
//
// The layer can be persisted to leveldb based storage for further use.
package dedupe

import (
	"crypto/sha1"
	"os"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/utils/conversion"
)

// Storage is a duplicate detecting storage for nuclei scan events.
type Storage struct {
	temporary string
	storage   *leveldb.DB
}

// New creates a new duplicate detecting storage for nuclei scan events.
func New(dbPath string) (*Storage, error) {
	storage := &Storage{}

	var err error
	if dbPath == "" {
		dbPath, err = os.MkdirTemp("", "nuclei-report-*")
		storage.temporary = dbPath
	}
	if err != nil {
		return nil, err
	}

	storage.storage, err = leveldb.OpenFile(dbPath, nil)
	if err != nil {
		if !errors.IsCorrupted(err) {
			return nil, err
		}

		// If the metadata is corrupted, try to recover
		storage.storage, err = leveldb.RecoverFile(dbPath, nil)
		if err != nil {
			return nil, err
		}
	}
	return storage, nil
}

func (s *Storage) Clear() {
	var keys [][]byte
	iter := s.storage.NewIterator(nil, nil)
	for iter.Next() {
		keys = append(keys, iter.Key())
	}
	iter.Release()
	for _, key := range keys {
		_ = s.storage.Delete(key, nil)
	}
}

// Close closes the storage for further operations
func (s *Storage) Close() {
	_ = s.storage.Close()
	if s.temporary != "" {
		_ = os.RemoveAll(s.temporary)
	}
}

// Index indexes an item in storage and returns true if the item
// was unique.
func (s *Storage) Index(result *output.ResultEvent) (bool, error) {
	hasher := sha1.New()
	if result.TemplateID != "" {
		_, _ = hasher.Write(conversion.Bytes(result.TemplateID))
	}
	if result.MatcherName != "" {
		_, _ = hasher.Write(conversion.Bytes(result.MatcherName))
	}
	if result.ExtractorName != "" {
		_, _ = hasher.Write(conversion.Bytes(result.ExtractorName))
	}
	if result.Type != "" {
		_, _ = hasher.Write(conversion.Bytes(result.Type))
	}
	if result.Host != "" {
		_, _ = hasher.Write(conversion.Bytes(result.Host))
	}
	if result.Matched != "" {
		_, _ = hasher.Write(conversion.Bytes(result.Matched))
	}
	for _, v := range result.ExtractedResults {
		_, _ = hasher.Write(conversion.Bytes(v))
	}
	for k, v := range result.Metadata {
		_, _ = hasher.Write(conversion.Bytes(k))
		_, _ = hasher.Write(conversion.Bytes(types.ToString(v)))
	}
	hash := hasher.Sum(nil)

	exists, err := s.storage.Has(hash, nil)
	if err != nil {
		// if we have an error, return with it but mark it as true
		// since we don't want to lose an issue considering it a dupe.
		return true, err
	}
	if !exists {
		return true, s.storage.Put(hash, nil, nil)
	}
	return false, err
}
