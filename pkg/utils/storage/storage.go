package storage

import (
	"fmt"
	"os"

	"github.com/cespare/xxhash/v2"
	"github.com/projectdiscovery/utils/conversion"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

type Storage struct {
	dbPath  string
	storage *leveldb.DB
}

func New() (*Storage, error) {
	storage := &Storage{}

	dbPath, err := os.MkdirTemp("", "nuclei-storage-*")
	storage.dbPath = dbPath
	if err != nil {
		return nil, err
	}

	storage.storage, err = leveldb.OpenFile(dbPath, &opt.Options{})
	if err != nil {
		return nil, err
	}
	return storage, nil
}

func (s *Storage) Close() {
	s.storage.Close()
	os.RemoveAll(s.dbPath)
}

func HashString(v string) uint64 {
	return Hash(conversion.Bytes(v))
}

func Hash(v []byte) uint64 {
	return xxhash.Sum64(v)
}

func (s *Storage) Get(k uint64) (string, error) {
	v, err := s.storage.Get(conversion.Bytes(fmt.Sprint(k)), nil)

	return conversion.String(v), err
}

func (s *Storage) SetString(v string) (uint64, error) {
	return s.Set(conversion.Bytes(v))
}

func (s *Storage) Set(v []byte) (uint64, error) {
	hash := Hash(v)

	return hash, s.storage.Put(conversion.Bytes(fmt.Sprint(hash)), v, nil)
}
