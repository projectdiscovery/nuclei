// Package hash exposes incremental hashes to nuclei JavaScript templates
// (require('nuclei/hash')), so a template can hash a response chunk by chunk
// as it reads it instead of holding the whole body.
package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"

	"github.com/spaolacci/murmur3"
)

type (
	// Hash is a running hash. Its memory does not grow with the data written.
	// @example
	// ```javascript
	// const hash = require('nuclei/hash');
	// const h = hash.New('sha256');
	// h.WriteString('hello');
	// log(h.Sum());
	// ```
	Hash struct {
		h    hash.Hash
		mmh3 bool
	}
)

// New returns a running hash for algorithm: md5, sha1, sha256, sha512 or
// mmh3. Sum gives the same value as the DSL function of the same name over
// all the data written.
// @example
// ```javascript
// const hash = require('nuclei/hash');
// const h = hash.New('sha256');
// ```
func New(algorithm string) (*Hash, error) {
	switch strings.ToLower(algorithm) {
	case "md5":
		return &Hash{h: md5.New()}, nil
	case "sha1":
		return &Hash{h: sha1.New()}, nil
	case "sha256":
		return &Hash{h: sha256.New()}, nil
	case "sha512":
		return &Hash{h: sha512.New()}, nil
	case "mmh3":
		return &Hash{h: murmur3.New32WithSeed(0), mmh3: true}, nil
	}
	return nil, fmt.Errorf("unsupported hash algorithm %q, expected md5, sha1, sha256, sha512 or mmh3", algorithm)
}

// Write adds data to the hash.
// @example
// ```javascript
// const hash = require('nuclei/hash');
// const h = hash.New('sha256');
// h.Write([104, 105]);
// ```
func (h *Hash) Write(data []byte) error {
	if h.h == nil {
		return errNotCreatedByNew
	}
	_, _ = h.h.Write(data)
	return nil
}

// WriteString adds the string data to the hash.
// @example
// ```javascript
// const hash = require('nuclei/hash');
// const h = hash.New('sha256');
// h.WriteString('hi');
// ```
func (h *Hash) WriteString(data string) error {
	return h.Write([]byte(data))
}

// Sum returns the hash of the data written so far: lowercase hex, or for
// mmh3 a signed decimal integer. Writing more afterwards continues the hash.
// @example
// ```javascript
// const hash = require('nuclei/hash');
// const h = hash.New('mmh3');
// h.WriteString('hello');
// log(h.Sum());
// ```
func (h *Hash) Sum() (string, error) {
	if h.h == nil {
		return "", errNotCreatedByNew
	}
	if h.mmh3 {
		return fmt.Sprintf("%d", int32(h.h.(hash.Hash32).Sum32())), nil
	}
	return hex.EncodeToString(h.h.Sum(nil)), nil
}

// The module also exposes Hash as a class, and new hash.Hash() has no
// algorithm.
var errNotCreatedByNew = errors.New("hash was not created with hash.New")
