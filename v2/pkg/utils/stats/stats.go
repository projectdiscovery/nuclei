package stats

import (
	"sync"
	"sync/atomic"

	"github.com/projectdiscovery/gologger"
)

// Storage is a storage for storing statistics information
// about the nuclei engine displaying it at user-defined intervals.
type Storage struct {
	data  map[string]*storageDataItem
	mutex *sync.RWMutex
}

type storageDataItem struct {
	description string
	value       int64
}

var Default *Storage

func init() {
	Default = New()
}

// NewEntry creates a new entry in the storage object
func NewEntry(name, description string) {
	Default.NewEntry(name, description)
}

// Increment increments the value for a name string
func Increment(name string) {
	Default.Increment(name)
}

// Display displays the stats for a name
func Display(name string) {
	Default.Display(name)
}

// GetValue returns the value for a set variable
func GetValue(name string) int64 {
	return Default.GetValue(name)
}

// New creates a new storage object
func New() *Storage {
	return &Storage{data: make(map[string]*storageDataItem), mutex: &sync.RWMutex{}}
}

// NewEntry creates a new entry in the storage object
func (s *Storage) NewEntry(name, description string) {
	s.mutex.Lock()
	s.data[name] = &storageDataItem{description: description, value: 0}
	s.mutex.Unlock()
}

// Increment increments the value for a name string
func (s *Storage) Increment(name string) {
	s.mutex.RLock()
	data, ok := s.data[name]
	s.mutex.RUnlock()
	if !ok {
		return
	}

	atomic.AddInt64(&data.value, 1)
}

// Display displays the stats for a name
func (s *Storage) Display(name string) {
	s.mutex.RLock()
	data, ok := s.data[name]
	s.mutex.RUnlock()
	if !ok {
		return
	}

	dataValue := atomic.LoadInt64(&data.value)
	if dataValue == 0 {
		return // don't show for nil stats
	}
	gologger.Error().Label("WRN").Msgf(data.description, dataValue)
}

// GetValue returns the value for a set variable
func (s *Storage) GetValue(name string) int64 {
	s.mutex.RLock()
	data, ok := s.data[name]
	s.mutex.RUnlock()
	if !ok {
		return 0
	}

	dataValue := atomic.LoadInt64(&data.value)
	return dataValue
}
