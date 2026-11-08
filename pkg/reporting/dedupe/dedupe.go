// Package dedupe implements deduplication layer for nuclei-generated
// issues.
//
// The layer can be persisted to leveldb based storage for further use.
package dedupe

import (
	"crypto/sha1"
	"encoding/binary"
	"os"
	"slices"
	"sync"

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
	mu        sync.Mutex
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
// was unique. Concurrent checks and inserts are serialized.
func (s *Storage) Index(result *output.ResultEvent) (bool, error) {
	hasher := sha1.New()

	// Lengths preserve field and collection boundaries, including empty values.
	writeLength := func(length int) {
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], uint64(length))
		_, _ = hasher.Write(buf[:])
	}

	writeString := func(value string) {
		writeLength(len(value))
		_, _ = hasher.Write(conversion.Bytes(value))
	}

	for _, value := range []string{
		result.TemplateID, result.MatcherName, result.ExtractorName, result.Type,
		result.Host, result.Port, result.Scheme, result.URL, result.Matched,
	} {
		writeString(value)
	}

	writeLength(len(result.ExtractedResults))

	for _, v := range result.ExtractedResults {
		writeString(v)
	}

	writeLength(len(result.Metadata))

	keys := make([]string, 0, len(result.Metadata))
	for k := range result.Metadata {
		keys = append(keys, k)
	}

	slices.Sort(keys)
	for _, k := range keys {
		writeString(k)
		writeString(types.ToString(result.Metadata[k]))
	}

	// Version 2 keys cannot reuse legacy hashes that omitted the input origin.
	key := make([]byte, 1, 1+sha1.Size)
	key[0] = 2
	hash := hasher.Sum(key)

	// LevelDB synchronizes individual operations, not this check and insert.
	s.mu.Lock()
	defer s.mu.Unlock()

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
