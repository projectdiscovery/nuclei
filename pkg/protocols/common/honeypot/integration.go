package honeypot

import (
	"fmt"
	"os"
	"sync"
)

var (
	// globalDetector is the singleton honeypot detector instance
	globalDetector *Detector
	
	// once ensures the detector is initialized only once
	once sync.Once
	
	// enabled indicates if honeypot detection is enabled
	enabled bool
	
	// mu protects enabled flag
	mu sync.RWMutex
)

// Initialize sets up the global honeypot detector
// Should be called once at application startup
func Initialize(threshold int) {
	once.Do(func() {
		globalDetector = New(Config{
			Threshold: threshold,
			OnHoneypotDetected: func(host string, matchCount int) {
				// Default warning callback - use stderr to avoid polluting stdout/JSON output
				fmt.Fprintf(os.Stderr, "[WARN] %s matched %d templates → possible honeypot.\n", host, matchCount)
			},
		})
	})
}

// Enable turns on honeypot detection
func Enable() {
	mu.Lock()
	defer mu.Unlock()
	enabled = true
}

// Disable turns off honeypot detection
func Disable() {
	mu.Lock()
	defer mu.Unlock()
	enabled = false
}

// IsEnabled returns whether honeypot detection is enabled
func IsEnabled() bool {
	mu.RLock()
	defer mu.RUnlock()
	return enabled
}

// Record records a template match for a host if detection is enabled
// Returns true if this match triggered honeypot detection
func Record(host, templateID string) bool {
	if !IsEnabled() {
		return false
	}
	
	if globalDetector == nil {
		Initialize(20) // use default threshold
	}
	
	return globalDetector.RecordMatch(host, templateID)
}

// Check checks if a host is flagged as a honeypot
func Check(host string) bool {
	if !IsEnabled() || globalDetector == nil {
		return false
	}
	
	return globalDetector.IsHoneypot(host)
}

// GetMatchCount returns the number of template matches for a host
func GetMatchCount(host string) int {
	if globalDetector == nil {
		return 0
	}
	
	return globalDetector.GetMatchCount(host)
}

// GetScore returns the honeypot score for a host
func GetScore(host string) int {
	if globalDetector == nil {
		return 0
	}
	
	return globalDetector.GetScore(host)
}

// SetCallback sets a custom callback for honeypot detection
func SetCallback(callback func(host string, matchCount int)) {
	if globalDetector == nil {
		Initialize(20)
	}
	
	globalDetector.onHoneypotDetected = callback
}

// SetThreshold updates the detection threshold
func SetThreshold(threshold int) {
	if globalDetector == nil {
		Initialize(threshold)
		return
	}
	
	globalDetector.SetThreshold(threshold)
}

// GetStats returns detection statistics
func GetStats() Stats {
	if globalDetector == nil {
		return Stats{}
	}
	
	return globalDetector.GetStats()
}

// Reset clears all tracked data
func Reset() {
	if globalDetector != nil {
		globalDetector.Reset()
	}
}
