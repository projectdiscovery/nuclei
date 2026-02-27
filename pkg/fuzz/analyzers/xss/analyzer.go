package xss

import (
	"crypto/rand"
	"io"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

// Analyzer is an XSS context analyzer for the fuzzer.
// It injects a canary value and uses gotreesitter AST parsing to determine
// the precise HTML/JS/CSS context of each reflection point.
type Analyzer struct{}

var _ analyzers.Analyzer = &Analyzer{}

const defaultMaxResponseBodySize = 10 * 1024 * 1024 // 10 MB

func init() {
	analyzers.RegisterAnalyzer("xss_context", &Analyzer{})
}

// Name returns the name of this analyzer.
func (a *Analyzer) Name() string {
	return "xss_context"
}

// ApplyInitialTransformation applies payload transformations.
// For XSS context analysis, we don't transform the initial payload since
// we generate our own canary in Analyze().
func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	return analyzers.ApplyPayloadTransformations(data)
}

// Analyze sends a request with a unique canary value and determines the
// XSS context of all reflection points using AST parsing.
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	canary := generateCanary()

	gr := options.FuzzGenerated
	if err := gr.Component.SetValue(gr.Key, canary); err != nil {
		return false, "", errors.Wrap(err, "could not set canary value")
	}

	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return false, "", errors.Wrap(err, "could not rebuild request with canary")
	}

	resp, err := options.HttpClient.Do(rebuilt)
	if err != nil {
		return false, "", errors.Wrap(err, "could not send canary request")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, defaultMaxResponseBodySize))
	if err != nil {
		return false, "", errors.Wrap(err, "could not read response body")
	}

	// Quick check: if canary is not reflected at all, no XSS
	if !strings.Contains(string(body), canary) {
		return false, "", nil
	}

	// Parse HTML and find all reflection contexts
	points := findReflections(body, canary)
	if len(points) == 0 {
		return false, "", nil
	}

	// Build details string listing all unique contexts
	seen := make(map[XSSContext]bool)
	var details []string
	for _, p := range points {
		if !seen[p.Context] {
			seen[p.Context] = true
			details = append(details, p.Context.String())
		}
	}

	return true, strings.Join(details, ", "), nil
}

// generateCanary creates a unique canary string unlikely to appear in natural content.
// Format: "gtss" + 8 random alphanumeric characters.
func generateCanary() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to a fixed canary if crypto/rand fails (extremely unlikely)
		return "gtss00000000"
	}
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return "gtss" + string(b)
}
