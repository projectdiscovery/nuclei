package protocolstate

import (
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// ExpiringSet is a lock-free-read set of string keys with per-entry expiry.
// Cleanup is amortized across writes and also performed by Keys.
type ExpiringSet struct {
	values          sync.Map // string -> expiry UnixNano
	cleanupInterval time.Duration
	lastCleanup     atomic.Int64
}

func NewExpiringSet(cleanupInterval time.Duration) *ExpiringSet {
	set := &ExpiringSet{cleanupInterval: cleanupInterval}
	set.lastCleanup.Store(time.Now().UnixNano())
	return set
}

func (s *ExpiringSet) Store(key string, ttl time.Duration) {
	s.StoreUntil(key, time.Now().Add(ttl))
}

func (s *ExpiringSet) StoreUntil(key string, expiry time.Time) {
	if s == nil || key == "" {
		return
	}
	s.values.Store(key, expiry.UnixNano())
	s.maybeCleanup(time.Now())
}

func (s *ExpiringSet) Contains(key string) bool {
	return s.containsAt(key, time.Now())
}

func (s *ExpiringSet) containsAt(key string, now time.Time) bool {
	if s == nil || key == "" {
		return false
	}
	value, ok := s.values.Load(key)
	if !ok {
		return false
	}
	expiresAt, ok := value.(int64)
	if !ok || now.UnixNano() >= expiresAt {
		s.values.CompareAndDelete(key, value)
		return false
	}
	return true
}

func (s *ExpiringSet) Keys() []string {
	return s.keysAt(time.Now())
}

func (s *ExpiringSet) keysAt(now time.Time) []string {
	if s == nil {
		return nil
	}
	var keys []string
	s.values.Range(func(key, value any) bool {
		name, keyOK := key.(string)
		expiresAt, expiryOK := value.(int64)
		if keyOK && expiryOK && now.UnixNano() < expiresAt {
			keys = append(keys, name)
		} else {
			s.values.CompareAndDelete(key, value)
		}
		return true
	})
	slices.Sort(keys)
	return keys
}

func (s *ExpiringSet) maybeCleanup(now time.Time) {
	if s.cleanupInterval <= 0 {
		return
	}
	last := s.lastCleanup.Load()
	if now.UnixNano()-last < s.cleanupInterval.Nanoseconds() ||
		!s.lastCleanup.CompareAndSwap(last, now.UnixNano()) {
		return
	}
	s.keysAt(now)
}
