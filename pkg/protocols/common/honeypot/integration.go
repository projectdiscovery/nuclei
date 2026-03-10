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
	// Atomically snapshot both enabled state and detector reference
	// This prevents TOCTOU race between IsEnabled() and detector access
	mu.RLock()
	isEnabled := enabled
	detector := globalDetector
	mu.RUnlock()
	
	if !isEnabled {
		return false
	}
	
	if detector == nil {
		Initialize(20) // use default threshold
		detector = globalDetector
	}
	
	return detector.RecordMatch(host, templateID)
}

// Check checks if a host is flagged as a honeypot
func Check(host string) bool {
	mu.RLock()
	isEnabled := enabled
	detector := globalDetector
	mu.RUnlock()
	
	if !isEnabled || detector == nil {
		return false
	}
	
	return detector.IsHoneypot(host)
}

// GetMatchCount returns the number of template matches for a host
func GetMatchCount(host string) int {
	mu.RLock()
	detector := globalDetector
	mu.RUnlock()
	
	if detector == nil {
		return 0
	}
	
	return detector.GetMatchCount(host)
}

// GetScore returns the honeypot score for a host
func GetScore(host string) int {
	mu.RLock()
	detector := globalDetector
	mu.RUnlock()
	
	if detector == nil {
		return 0
	}
	
	return detector.GetScore(host)
}

// SetCallback sets a custom callback for honeypot detection
func SetCallback(callback func(host string, matchCount int)) {
	mu.RLock()
	detector := globalDetector
	mu.RUnlock()
	
	if detector == nil {
		Initialize(20)
		mu.RLock()
		detector = globalDetector
		mu.RUnlock()
	}
	
	detector.onHoneypotDetected = callback
}

// SetThreshold updates the detection threshold
func SetThreshold(threshold int) {
	mu.RLock()
	detector := globalDetector
	mu.RUnlock()
	
	if detector == nil {
		Initialize(threshold)
		return
	}
	
	detector.SetThreshold(threshold)
}

// GetStats returns detection statistics
func GetStats() Stats {
	mu.RLock()
	detector := globalDetector
	mu.RUnlock()
	
	if detector == nil {
		return Stats{}
	}
	
	return detector.GetStats()
}

// Reset clears all tracked data
func Reset() {
	mu.RLock()
	detector := globalDetector
	mu.RUnlock()
	
	if detector != nil {
		detector.Reset()
	}
}
