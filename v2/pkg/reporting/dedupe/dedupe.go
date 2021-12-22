// Package dedupe implements deduplication layer for nuclei-generated
// issues.
//
// The layer can be persisted to leveldb based storage for further use.
package dedupe

import (
	"io/ioutil"
	"os"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"

	"github.com/projectdiscovery/nuclei/v2/pkg/output"
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
		dbPath, err = ioutil.TempDir("", "nuclei-report-*")
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

// Close closes the storage for further operations
func (s *Storage) Close() {
	s.storage.Close()
	if s.temporary != "" {
		os.RemoveAll(s.temporary)
	}
}

// Index indexes an item in storage and returns true if the item
// was unique.
func (s *Storage) Index(result *output.ResultEvent) (bool, error) {
	hash := []byte(result.Hash())

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
