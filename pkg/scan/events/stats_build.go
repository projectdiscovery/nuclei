//go:build stats
// +build stats

package events

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

var _ ScanEventWorker = &ScanStatsWorker{}

var defaultWorker = &ScanStatsWorker{}

// ScanStatsWorker is a worker for scanning stats
// This tracks basic stats in jsonlines format
// in given directory or a default directory with name stats_{timestamp} in the current directory
type ScanStatsWorker struct {
	config    *ScanConfig
	m         *sync.Mutex
	directory string
	file      *os.File
	enc       *json.Encoder
}

// Init initializes the scan stats worker
func InitWithConfig(config *ScanConfig, statsDirectory string) {
	currentTime := time.Now().Format("20060102150405")
	dirName := fmt.Sprintf("nuclei-stats-%s", currentTime)
	err := os.Mkdir(dirName, 0755)
	if err != nil {
		panic(err)
	}
	// save the config to the directory
	bin, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(filepath.Join(dirName, ConfigFile), bin, 0755)
	if err != nil {
		panic(err)
	}
	defaultWorker = &ScanStatsWorker{config: config, m: &sync.Mutex{}, directory: dirName}
	err = defaultWorker.initEventsFile()
	if err != nil {
		panic(err)
	}
}

// initEventsFile initializes the events file for the worker
func (s *ScanStatsWorker) initEventsFile() error {
	f, err := os.Create(filepath.Join(s.directory, EventsFile))
	if err != nil {
		return err
	}
	s.file = f
	s.enc = json.NewEncoder(f)
	return nil
}

// AddScanEvent adds a scan event to the worker
func (s *ScanStatsWorker) AddScanEvent(event ScanEvent) {
	s.m.Lock()
	defer s.m.Unlock()

	err := s.enc.Encode(event)
	if err != nil {
		panic(err)
	}
}

// AddScanEvent adds a scan event to the worker
func AddScanEvent(event ScanEvent) {
	if defaultWorker == nil {
		return
	}
	defaultWorker.AddScanEvent(event)
}

// Close closes the file associated with the worker
func (s *ScanStatsWorker) Close() {
	s.m.Lock()
	defer s.m.Unlock()

	if s.file != nil {
		_ = s.file.Close()
		s.file = nil
	}
}

// Close closes the file associated with the worker
func Close() {
	if defaultWorker == nil {
		return
	}
	defaultWorker.Close()
}
