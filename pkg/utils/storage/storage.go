package storage

import (
	"crypto/sha1"
	"encoding/hex"
	"os"

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

func Hash(v []byte) []byte {
	hasher := sha1.New()
	_, _ = hasher.Write(v)
	return hasher.Sum(nil)
}

func HashString(v []byte) string {
	return hex.EncodeToString(v)
}

func HashBytes(v string) []byte {
	hash, _ := hex.DecodeString(v)
	return hash
}

func (s *Storage) Get(k string) (string, error) {
	hash := HashBytes(k)

	v, err := s.storage.Get(hash, nil)

	return conversion.String(v), err
}

func (s *Storage) SetString(v string) (string, error) {
	return s.Set(conversion.Bytes(v))
}

func (s *Storage) Set(v []byte) (string, error) {
	hash := Hash(v)

	return HashString(hash), s.storage.Put(hash, v, nil)
}
