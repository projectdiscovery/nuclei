package honeypot

import (
	"context"
	"fmt"
	"sync"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"golang.org/x/sync/singleflight"
)

// TargetFilter provides thread-safe honeypot detection and filtering functionality
// with caching of detection results for improved performance.
type TargetFilter struct {
	// detector performs the actual honeypot detection analysis
	detector *Detector
	// logger handles debug and informational logging
	logger *gologger.Logger
	// colorizer provides colored output for terminal warnings
	colorizer aurora.Aurora
	// results caches detection results to avoid redundant scanning
	results map[string]*DetectionResult
	// resultMutex protects concurrent access to the results cache
	resultMutex sync.RWMutex
	// detectGroup coalesces concurrent detection requests for the same target
	detectGroup singleflight.Group
}

// NewTargetFilter creates a new target filter for honeypot detection
func NewTargetFilter(opts *Options, logger *gologger.Logger, colorizer aurora.Aurora) *TargetFilter {
	return &TargetFilter{
		detector:  NewDetector(opts),
		logger:    logger,
		colorizer: colorizer,
		results:   make(map[string]*DetectionResult),
	}
}

// CheckTarget checks if a target is a honeypot
// Returns true if the target should be skipped (is a honeypot)
func (tf *TargetFilter) CheckTarget(ctx context.Context, target string) (bool, *DetectionResult) {
	// Check cache first
	tf.resultMutex.RLock()
	if result, exists := tf.results[target]; exists {
		tf.resultMutex.RUnlock()
		return result.IsHoneypot, result
	}
	tf.resultMutex.RUnlock()

	// Use singleflight to coalesce concurrent detection requests
	v, err, _ := tf.detectGroup.Do(target, func() (interface{}, error) {
		// Double-check cache after acquiring singleflight lock
		tf.resultMutex.RLock()
		if result, exists := tf.results[target]; exists {
			tf.resultMutex.RUnlock()
			return result, nil
		}
		tf.resultMutex.RUnlock()

		// Perform detection
		result, err := tf.detector.Detect(ctx, target)
		if err != nil {
			if tf.logger != nil {
				tf.logger.Debug().Msgf("Honeypot detection error for %s: %v", target, err)
			}
			return nil, err
		}

		// Cache result
		tf.resultMutex.Lock()
		tf.results[target] = result
		tf.resultMutex.Unlock()

		return result, nil
	})

	if err != nil {
		return false, nil
	}

	result, ok := v.(*DetectionResult)
	if !ok || result == nil {
		return false, nil
	}

	return result.IsHoneypot, result
}

// PrintWarning prints a warning message about detected honeypot
func (tf *TargetFilter) PrintWarning(result *DetectionResult) {
	if result == nil || !result.IsHoneypot {
		return
	}

	if tf.logger != nil {
		warningMsg := fmt.Sprintf("Target is a suspected honeypot: %s [Type: %s, Confidence: %.0f%%]",
			result.Target, result.Type, result.Confidence*100)

		if tf.colorizer != nil {
			warningMsg = fmt.Sprintf("%s", tf.colorizer.BrightYellow(warningMsg))
		}

		tf.logger.Warning().Msg(warningMsg)

		// Print indicators in verbose mode
		for _, indicator := range result.Indicators {
			tf.logger.Debug().Msgf("  - Indicator: %s", indicator)
		}
	}
}

// GetResults returns all cached detection results.
// The returned map is a shallow copy; DetectionResult pointers are shared with the cache.
// Callers must not modify the returned DetectionResult objects to maintain cache integrity.
func (tf *TargetFilter) GetResults() map[string]*DetectionResult {
	tf.resultMutex.RLock()
	defer tf.resultMutex.RUnlock()

	// Return a shallow copy to prevent map race conditions
	// DetectionResult objects are immutable and shared with cache
	results := make(map[string]*DetectionResult, len(tf.results))
	for k, v := range tf.results {
		results[k] = v
	}
	return results
}

// IsHoneypot returns whether a target has been identified as a honeypot.
// This method should only be called after CheckTarget has been run for the target.
// Returns (isHoneypot, hasBeenChecked). If hasBeenChecked is false, detection has not been performed yet.
func (tf *TargetFilter) IsHoneypot(target string) (isHoneypot bool, hasBeenChecked bool) {
	tf.resultMutex.RLock()
	defer tf.resultMutex.RUnlock()

	result, exists := tf.results[target]
	if !exists {
		return false, false
	}
	return result.IsHoneypot, true
}

// Clear clears the cached detection results
func (tf *TargetFilter) Clear() {
	tf.resultMutex.Lock()
	defer tf.resultMutex.Unlock()
	tf.results = make(map[string]*DetectionResult)
}
