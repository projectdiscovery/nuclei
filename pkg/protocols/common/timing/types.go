package timing

import "time"

// ValidationFunc defines the function signature for behavioral validation.
// It returns the HTTP status code and an error if the request failed.
type ValidationFunc func() (int, error)

// TimingResult holds the statistical analysis of the timing probes.
type TimingResult struct {
	// Phase 1: Latency Metrics
	MinRTT                 time.Duration   `json:"min_rtt"`
	MaxRTT                 time.Duration   `json:"max_rtt"`
	AvgRTT                 time.Duration   `json:"avg_rtt"`
	StdDev                 time.Duration   `json:"std_dev"`
	CoefficientOfVariation float64         `json:"coefficient_of_variation"`
	IsStaticLatency        bool            `json:"is_static_latency"`
	RawRTTs                []time.Duration `json:"raw_rtts,omitempty"` // Optional: for debugging

	// Phase 3: Behavioral Validation Metrics
	ValidationAttempted bool   `json:"validation_attempted"`
	ReadStatusCode      int    `json:"read_status_code"`
	DeleteStatusCode    int    `json:"delete_status_code"`
	IsStateless         bool   `json:"is_stateless"`
	Verdict             string `json:"verdict"`
}

// Options defines configuration for the timing analyzer.
type Options struct {
	Iterations        int           // Number of requests to perform (default: 5)
	StaticThresholdCV float64       // Coefficient of Variation threshold for static detection (default: 0.05)
	SleepInterval     time.Duration // Time to wait between requests to avoid rate limiting

	// Phase 3: Behavioral Validation Configuration
	ValidationRead   ValidationFunc // Executes the Read/Check request
	ValidationDelete ValidationFunc // Executes the Delete/Cleanup request
}

// ValidationSpec defines the configuration for behavioral state checks (used in YAML parsing)
type ValidationSpec struct {
	ReadPath   string `yaml:"read_path" jsonschema:"title=read path to verify state persistence"`
	DeletePath string `yaml:"delete_path" jsonschema:"title=delete path to cleanup state"`
}

// TimingRequest is the configuration for the timing analysis probe (used in YAML parsing)
type TimingRequest struct {
	Path        string            `yaml:"path"`
	Method      string            `yaml:"method"`
	Body        string            `yaml:"body"`
	Headers     map[string]string `yaml:"headers"`
	Iterations  int               `yaml:"iterations"`
	ThresholdCV float64           `yaml:"threshold_cv"`
	Validation  *ValidationSpec   `yaml:"validation"`
}

// TimingError custom error type
type TimingError struct {
	Msg string
}

func (e *TimingError) Error() string {
	return e.Msg
}
