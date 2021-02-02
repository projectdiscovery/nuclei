// Package dedupe implements deduplication layer for nuclei-generated
// issues.
//
// The layer can be persisted to leveldb based storage for further use.
package dedupe

import (
	"crypto/sha1"
	"path"
	"unsafe"

	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
)

// Storage is a duplicate detecting storage for nuclei scan events.
type Storage struct {
	storage *leveldb.DB
}

const storageFilename = "nuclei-events.db"

// New creates a new duplicate detecting storage for nuclei scan events.
func New(folder string) (*Storage, error) {
	path := path.Join(folder, storageFilename)

	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		if !errors.IsCorrupted(err) {
			return nil, err
		}

		// If the metadata is corrupted, try to recover
		db, err = leveldb.RecoverFile(path, nil)
		if err != nil {
			return nil, err
		}
	}
	return &Storage{storage: db}, nil
}

// Close closes the storage for further operations
func (s *Storage) Close() {
	s.storage.Close()
}

// Index indexes an item in storage and returns true if the item
// was unique.
func (s *Storage) Index(result *output.ResultEvent) (bool, error) {
	hasher := sha1.New()
	if result.TemplateID != "" {
		hasher.Write(unsafeToBytes(result.TemplateID))
	}
	if result.MatcherName != "" {
		hasher.Write(unsafeToBytes(result.MatcherName))
	}
	if result.ExtractorName != "" {
		hasher.Write(unsafeToBytes(result.ExtractorName))
	}
	if result.Type != "" {
		hasher.Write(unsafeToBytes(result.Type))
	}
	if result.Host != "" {
		hasher.Write(unsafeToBytes(result.Host))
	}
	if result.Matched != "" {
		hasher.Write(unsafeToBytes(result.Matched))
	}
	for _, v := range result.ExtractedResults {
		hasher.Write(unsafeToBytes(v))
	}
	for k, v := range result.Metadata {
		hasher.Write(unsafeToBytes(k))
		hasher.Write(unsafeToBytes(types.ToString(v)))
	}
	if result.Request != "" {
		hasher.Write(unsafeToBytes(result.Request)) // Very dumb, change later.
	}
	hash := hasher.Sum(nil)

	exists, err := s.storage.Has(hash, nil)
	if err != nil {
		// if we have an error, return with it but mark it as true
		// since we don't want to loose an issue considering it a dupe.
		return true, err
	}
	if !exists {
		return true, s.storage.Put(hash, nil, nil)
	}
	return false, err
}

// unsafeToBytes converts a string to byte slice and does it with
// zero allocations.
//
// Reference - https://stackoverflow.com/questions/59209493/how-to-use-unsafe-get-a-byte-slice-from-a-string-without-memory-copy
func unsafeToBytes(data string) []byte {
	return *(*[]byte)(unsafe.Pointer(&data))
}
