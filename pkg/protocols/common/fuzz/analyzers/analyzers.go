package analyzers

import (
	"fmt"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/fuzz/component"
	"github.com/projectdiscovery/retryablehttp-go"
)

type AnalyzerType string

const (
	TimeDelay AnalyzerType = "time-delay"
	Heuristic AnalyzerType = "heuristic"
)

// Analysis is an analysis of a request using a specific analyzer
type Analysis struct {
	Matched  bool     `json:"matched"`
	Reasons  []string `json:"reasons"`
	Analyzer string   `json:"analyzer"`

	VulnerableRequest *retryablehttp.Request `json:"-"`
}

// AnalyzerInput is the input for an analyzer
type AnalyzerInput struct {
	Key           string
	Value         string
	OriginalValue string
	Request       *retryablehttp.Request
	Component     component.Component
	FinalArgs     map[string]interface{}
}

// Analyzer is an interface implemented by all fuzzing analyzers
type Analyzer interface {
	// Analyze analyzes the normalized request with a mutation
	Analyze(httpclient *retryablehttp.Client, input *AnalyzerInput) (*Analysis, error)
}

// GetAnalyzer returns a new analyzer for the given type
func GetAnalyzer(analyzerType string) (Analyzer, error) {
	switch analyzerType {
	case string(TimeDelay):
		return &TimeDelayAnalyzer{}, nil
	case string(Heuristic):
		return &HeuristicsAnalyzer{}, nil
	default:
		return nil, fmt.Errorf("invalid analyzer type: %s", analyzerType)
	}
}
