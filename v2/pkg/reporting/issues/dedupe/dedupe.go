// Package dedupe implements deduplication layer for nuclei-generated
// issues.
//
// The layer can be persisted to leveldb based storage for further use.
package dedupe

import (
	"crypto/sha1"
	"io/ioutil"
	"os"
	"unsafe"

	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
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
	hasher := sha1.New()
	if result.TemplateID != "" {
		_, _ = hasher.Write(unsafeToBytes(result.TemplateID))
	}
	if result.MatcherName != "" {
		_, _ = hasher.Write(unsafeToBytes(result.MatcherName))
	}
	if result.ExtractorName != "" {
		_, _ = hasher.Write(unsafeToBytes(result.ExtractorName))
	}
	if result.Type != "" {
		_, _ = hasher.Write(unsafeToBytes(result.Type))
	}
	if result.Host != "" {
		_, _ = hasher.Write(unsafeToBytes(result.Host))
	}
	if result.Matched != "" {
		_, _ = hasher.Write(unsafeToBytes(result.Matched))
	}
	for _, v := range result.ExtractedResults {
		_, _ = hasher.Write(unsafeToBytes(v))
	}
	for k, v := range result.Metadata {
		_, _ = hasher.Write(unsafeToBytes(k))
		_, _ = hasher.Write(unsafeToBytes(types.ToString(v)))
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
