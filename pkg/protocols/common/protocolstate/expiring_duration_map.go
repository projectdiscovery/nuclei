package protocolstate

import (
	"sync"
	"sync/atomic"
	"time"
)

type expiringDuration struct {
	value     int64
	expiresAt int64
}

// ExpiringDurationMap stores the smallest observed duration for each key and
// evicts values that have not been refreshed before their TTL.
type ExpiringDurationMap struct {
	entries         sync.Map
	cleanupInterval time.Duration
	lastCleanup     atomic.Int64
}

// NewExpiringDurationMap creates a duration map with opportunistic cleanup.
func NewExpiringDurationMap(cleanupInterval time.Duration) *ExpiringDurationMap {
	return &ExpiringDurationMap{cleanupInterval: cleanupInterval}
}

// StoreMin records value when it is smaller than the current unexpired value.
// Every observation refreshes the entry's expiry.
func (m *ExpiringDurationMap) StoreMin(key string, value, ttl time.Duration) {
	if m == nil || key == "" || value <= 0 || ttl <= 0 {
		return
	}
	now := time.Now()
	nextExpiry := now.Add(ttl).UnixNano()
	for {
		loaded, ok := m.entries.Load(key)
		if !ok {
			if _, loaded := m.entries.LoadOrStore(key, expiringDuration{
				value: value.Nanoseconds(), expiresAt: nextExpiry,
			}); !loaded {
				m.maybeCleanup(now)
				return
			}
			continue
		}

		current, ok := loaded.(expiringDuration)
		if !ok {
			if m.entries.CompareAndSwap(key, loaded, expiringDuration{
				value: value.Nanoseconds(), expiresAt: nextExpiry,
			}) {
				m.maybeCleanup(now)
				return
			}
			continue
		}

		nextValue := value.Nanoseconds()
		if current.expiresAt > now.UnixNano() && current.value < nextValue {
			nextValue = current.value
		}
		next := expiringDuration{value: nextValue, expiresAt: nextExpiry}
		if m.entries.CompareAndSwap(key, current, next) {
			m.maybeCleanup(now)
			return
		}
	}
}

// Load returns an unexpired duration.
func (m *ExpiringDurationMap) Load(key string) (time.Duration, bool) {
	if m == nil || key == "" {
		return 0, false
	}
	loaded, ok := m.entries.Load(key)
	if !ok {
		return 0, false
	}
	current, ok := loaded.(expiringDuration)
	if !ok || current.value <= 0 {
		m.entries.CompareAndDelete(key, loaded)
		return 0, false
	}
	if current.expiresAt <= time.Now().UnixNano() {
		m.entries.CompareAndDelete(key, current)
		return 0, false
	}
	return time.Duration(current.value), true
}

func (m *ExpiringDurationMap) maybeCleanup(now time.Time) {
	if m.cleanupInterval <= 0 {
		return
	}
	cutoff := now.Add(-m.cleanupInterval).UnixNano()
	previous := m.lastCleanup.Load()
	if previous > cutoff || !m.lastCleanup.CompareAndSwap(previous, now.UnixNano()) {
		return
	}
	m.entries.Range(func(key, loaded any) bool {
		current, ok := loaded.(expiringDuration)
		if !ok || current.expiresAt <= now.UnixNano() {
			m.entries.CompareAndDelete(key, loaded)
		}
		return true
	})
}
