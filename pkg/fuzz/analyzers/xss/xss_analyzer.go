package xss

import (
	"io"
	"net/http"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

// XSSAnalyzer implements the analyzers.Analyzer interface. It is invoked
// after a fuzz response is received and checks whether the fuzzing marker
// is reflected in the response body. If it is, the HTML context is
// classified and the result is surfaced to the caller.
type XSSAnalyzer struct{}

// compile-time interface check
var _ analyzers.Analyzer = &XSSAnalyzer{}

func init() {
	analyzers.RegisterAnalyzer("xss_context", &XSSAnalyzer{})
}

// Name returns the analyzer identifier used in template YAML.
func (a *XSSAnalyzer) Name() string {
	return "xss_context"
}

// ApplyInitialTransformation returns the payload unchanged.
// XSS context analysis does not pre-transform payloads; it classifies
// reflections after the fact.
func (a *XSSAnalyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	return analyzers.ApplyPayloadTransformations(data)
}

// Analyze reads the HTTP response body and determines whether the fuzz
// payload was reflected in an exploitable HTML context.
//
// It returns (true, explanation, nil) when an exploitable reflection is found,
// and (false, "", nil) otherwise.
func (a *XSSAnalyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	gr := options.FuzzGenerated

	resp, err := options.HttpClient.Do(gr.Request)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return false, "", nil
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MB limit
	if err != nil {
		return false, "", err
	}

	// Determine what the reflected marker is.
	// Use the final transformed fuzz value (gr.Value) so that the canary
	// matches what was actually sent to the server. Fall back to
	// gr.OriginalPayload only when gr.Value is empty.
	marker := gr.Value
	if marker == "" {
		marker = gr.OriginalPayload
	}
	if marker == "" {
		return false, "", nil
	}

	// Quick pre-check before full HTML parse
	if !strings.Contains(strings.ToLower(string(bodyBytes)), strings.ToLower(marker)) {
		return false, "", nil
	}

	// Gate expensive HTML context analysis on Content-Type.
	// JSON responses cannot contain exploitable HTML injection; for them we
	// skip straight to AnalyzeReflectionContext which will classify as
	// ContextJSON when appropriate. For all non-HTML content types we still
	// run the lightweight reflection check but skip the HTML tokenizer path.
	contentType := resp.Header.Get("Content-Type")
	isHTML := strings.Contains(strings.ToLower(contentType), "text/html") ||
		contentType == "" // empty CT: assume HTML for safety

	if !isHTML {
		// For non-HTML responses (e.g. application/json), only check JSON context.
		result := AnalyzeReflectionContext(string(bodyBytes), marker)
		if result.Context == ContextUnknown || result.Context != ContextJSON {
			return false, "", nil
		}
		if result.Confidence < 0.5 {
			return false, "", nil
		}
		explanation := result.Explanation
		if len(result.Payloads) > 0 {
			explanation += "\nSuggested payloads:\n"
			for _, p := range result.Payloads {
				explanation += "  - " + p + "\n"
			}
		}
		return true, explanation, nil
	}

	result := AnalyzeReflectionContext(string(bodyBytes), marker)
	if result.Context == ContextUnknown {
		return false, "", nil
	}

	// Surface exploitable sinks with higher confidence
	if result.Confidence < 0.5 {
		return false, "", nil
	}

	explanation := result.Explanation
	if len(result.Payloads) > 0 {
		explanation += "\nSuggested payloads:\n"
		for _, p := range result.Payloads {
			explanation += "  - " + p + "\n"
		}
	}

	return true, explanation, nil
}
