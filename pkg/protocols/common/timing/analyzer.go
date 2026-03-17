package timing

import (
	"math"
	"time"
)

// ProbeFunc defines the function signature for executing a single request probe.
// It returns the duration of the request and an error if the request failed.
// The implementation of this function should capture high-precision timing (time.Now().UnixNano()).
type ProbeFunc func() (time.Duration, error)

// TimingAnalyzer performs statistical analysis on request latencies.
type TimingAnalyzer struct {
	options Options
	probe   ProbeFunc
}

// NewTimingAnalyzer creates a new analyzer instance.
func NewTimingAnalyzer(options Options, probe ProbeFunc) *TimingAnalyzer {
	// Set sensible defaults
	if options.Iterations <= 0 {
		options.Iterations = 5
	}
	if options.StaticThresholdCV <= 0 {
		options.StaticThresholdCV = 0.05 // 5% variance threshold
	}

	return &TimingAnalyzer{
		options: options,
		probe:   probe,
	}
}

// ExecuteProbe runs the timing analysis loop and optional behavioral validation.
// It iterates N times, collects RTT data, calculates statistics, and validates state.
func (ta *TimingAnalyzer) ExecuteProbe() (*TimingResult, error) {
	results := &TimingResult{
		RawRTTs: make([]time.Duration, 0, ta.options.Iterations),
	}

	var sum time.Duration
	validCount := 0

	// Iterate N times to collect data
	for i := 0; i < ta.options.Iterations; i++ {
		// Execute the probe function (provided by the protocol implementation)
		duration, err := ta.probe()
		if err != nil {
			// If a request fails, we skip it but could log if needed.
			// Failed requests shouldn't skew timing stats.
			continue
		}

		// Capture the duration (High precision, usually nanoseconds)
		results.RawRTTs = append(results.RawRTTs, duration)
		sum += duration
		validCount++

		// Sleep between requests to avoid triggering IDS/WAF based on rate
		if ta.options.SleepInterval > 0 && i < ta.options.Iterations-1 {
			time.Sleep(ta.options.SleepInterval)
		}
	}

	// If no valid requests were completed, return error
	if validCount == 0 {
		return nil, ErrNoValidProbes
	}

	// Perform calculations
	ta.calculateBasicStats(results, sum, validCount)
	ta.calculateAdvancedStats(results)

	// --- Phase 3: Behavioral Validation ---
	ta.performValidation(results)

	// --- Final Verdict Derivation ---
	ta.deriveVerdict(results)

	return results, nil
}

// calculateBasicStats computes Min, Max, and Avg.
func (ta *TimingAnalyzer) calculateBasicStats(results *TimingResult, sum time.Duration, count int) {
	results.AvgRTT = time.Duration(int64(sum) / int64(count))

	// Initialize Min/Max with first valid value
	results.MinRTT = results.RawRTTs[0]
	results.MaxRTT = results.RawRTTs[0]

	for _, rtt := range results.RawRTTs {
		if rtt < results.MinRTT {
			results.MinRTT = rtt
		}
		if rtt > results.MaxRTT {
			results.MaxRTT = rtt
		}
	}
}

// calculateAdvancedStats computes Standard Deviation and Coefficient of Variation.
func (ta *TimingAnalyzer) calculateAdvancedStats(results *TimingResult) {
	n := len(results.RawRTTs)
	if n == 0 {
		return
	}

	// 1. Calculate Mean (float64 for precision)
	mean := float64(results.AvgRTT)

	// 2. Calculate Standard Deviation (Sample)
	// Using Sample Standard Deviation (N-1) as we are sampling the server's behavior
	var sumSqDiff float64
	for _, rtt := range results.RawRTTs {
		diff := float64(rtt) - mean
		sumSqDiff += diff * diff
	}

	var variance float64
	if n > 1 {
		variance = sumSqDiff / float64(n-1)
	} else {
		// If only 1 sample, variance is 0
		variance = 0
	}

	stdDev := math.Sqrt(variance)
	results.StdDev = time.Duration(stdDev)

	// 3. Calculate Coefficient of Variation (CV)
	// CV = StdDev / Mean
	// This normalizes the deviation relative to the average latency.
	if mean != 0 {
		results.CoefficientOfVariation = stdDev / mean
	} else {
		results.CoefficientOfVariation = 0
	}

	// 4. Determine IsStaticLatency
	// Logic: If CV is extremely low (near zero), the latency is perfectly static.
	// This strongly indicates a simulated delay or immediate processing without I/O.
	if results.CoefficientOfVariation <= ta.options.StaticThresholdCV {
		results.IsStaticLatency = true
	}

	// Edge case: If raw latency is extremely low (e.g., < 1ms) and consistent
	// This suggests a loopback or instant fake response
	if results.StdDev < time.Millisecond && results.AvgRTT < 5*time.Millisecond {
		results.IsStaticLatency = true
	}
}

// performValidation executes the behavioral state checks if configured.
func (ta *TimingAnalyzer) performValidation(results *TimingResult) {
	if ta.options.ValidationRead == nil {
		return
	}

	results.ValidationAttempted = true

	// Step 1: Execute Read Probe
	statusCode, err := ta.options.ValidationRead()
	if err != nil {
		// Network error during validation, cannot determine state.
		// We treat this as inconclusive.
		return
	}
	results.ReadStatusCode = statusCode

	// Step 2: Analyze Read Status
	// If Read returns 404, the state created in the main loop was not persisted.
	if results.ReadStatusCode == 404 {
		results.IsStateless = true
		return // No need to delete if it doesn't exist
	}

	// Step 3: Execute Delete Probe (Cleanup)
	if ta.options.ValidationDelete != nil {
		statusCode, err := ta.options.ValidationDelete()
		if err == nil {
			results.DeleteStatusCode = statusCode
		}
	}
}

// deriveVerdict determines the final classification based on metrics.
func (ta *TimingAnalyzer) deriveVerdict(results *TimingResult) {
	// Priority 1: Behavioral Analysis (Strongest Signal)
	if results.ValidationAttempted {
		if results.IsStateless {
			results.Verdict = "Stateless Honeypot"
			return
		}

		// Priority 2: Latency + Behavioral Correlation
		// If state was persisted (Not Stateless) AND latency is static
		if results.IsStaticLatency {
			results.Verdict = "Simulated Latency Honeypot"
			return
		}

		// Priority 3: Healthy State
		results.Verdict = "Likely Real Server"
		return
	}

	// Fallback if Validation not configured
	if results.IsStaticLatency {
		results.Verdict = "Suspicious Static Latency"
	} else {
		results.Verdict = "Normal Latency Profile"
	}
}

// Errors
var (
	ErrNoValidProbes = &TimingError{Msg: "no successful probes completed for timing analysis"}
)
