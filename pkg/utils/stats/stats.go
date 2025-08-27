package stats

import (
	"fmt"
	"sync/atomic"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// Storage is a storage for storing statistics information
// about the nuclei engine displaying it at user-defined intervals.
type Storage struct {
	data *mapsutil.SyncLockMap[string, *storageDataItem]
}

type storageDataItem struct {
	description string
	value       atomic.Int64
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

func DisplayAsWarning(name string) {
	Default.DisplayAsWarning(name)
}

// ForceDisplayWarning forces the display of a warning
// regardless of current verbosity level
func ForceDisplayWarning(name string) {
	Default.ForceDisplayWarning(name)
}

// GetValue returns the value for a set variable
func GetValue(name string) int64 {
	return Default.GetValue(name)
}

// New creates a new storage object
func New() *Storage {
	data := mapsutil.NewSyncLockMap[string, *storageDataItem]()
	return &Storage{data: data}
}

// NewEntry creates a new entry in the storage object
func (s *Storage) NewEntry(name, description string) {
	_ = s.data.Set(name, &storageDataItem{description: description, value: atomic.Int64{}})
}

// Increment increments the value for a name string
func (s *Storage) Increment(name string) {
	data, ok := s.data.Get(name)
	if !ok {
		return
	}
	data.value.Add(1)
}

// Display displays the stats for a name
func (s *Storage) Display(name string) {
	data, ok := s.data.Get(name)
	if !ok {
		return
	}

	dataValue := data.value.Load()
	if dataValue == 0 {
		return // don't show for nil stats
	}
	gologger.Error().Label("WRN").Msgf(data.description, dataValue)
}

func (s *Storage) DisplayAsWarning(name string) {
	data, ok := s.data.Get(name)
	if !ok {
		return
	}

	dataValue := data.value.Load()
	if dataValue == 0 {
		return // don't show for nil stats
	}
	gologger.Warning().Label("WRN").Msgf(data.description, dataValue)
}

// ForceDisplayWarning forces the display of a warning
// regardless of current verbosity level
func (s *Storage) ForceDisplayWarning(name string) {
	data, ok := s.data.Get(name)
	if !ok {
		return
	}

	dataValue := data.value.Load()
	if dataValue == 0 {
		return // don't show for nil stats
	}
	gologger.Print().Msgf("[%v] %v", aurora.BrightYellow("WRN"), fmt.Sprintf(data.description, dataValue))
}

// GetValue returns the value for a set variable
func (s *Storage) GetValue(name string) int64 {
	data, ok := s.data.Get(name)
	if !ok {
		return 0
	}

	return data.value.Load()
}
