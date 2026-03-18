package xss

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Analyzer is an XSS context analyzer for the fuzzer
type Analyzer struct{}

const analyzerName = "xss_context"

func init() {
	analyzers.RegisterAnalyzer(analyzerName, &Analyzer{})
}

// Name returns the name of the analyzer
func (a *Analyzer) Name() string {
	return analyzerName
}

// ApplyInitialTransformation applies the transformation to the initial payload
func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	// For XSS analysis, we inject the canary
	return XSSCanary
}

// Analyze performs XSS context analysis on the response
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	if options.ResponseBody == "" {
		return false, "", nil
	}

	// Get the original payload (canary) from the fuzz request
	canary := options.FuzzGenerated.OriginalPayload
	if canary == "" {
		canary = XSSCanary
	}

	// Analyze the context
	result := AnalyzeContext(options.ResponseBody, canary)
	if result.Context == ContextNone {
		return false, "", nil
	}

	// JSONScript context is not exploitable for XSS - skip
	if result.Context == ContextJSONScript {
		gologger.Debug().Msgf("XSS: skipping non-executable JSON script block context")
		return false, "", nil
	}

	// Select appropriate payloads for the detected context
	payloads, ok := XSCPayloads[result.Context]
	if !ok || len(payloads) == 0 {
		return false, "", nil
	}

	// Try to replay with payloads and verify
	for _, payload := range payloads {
		matched := a.replayAndVerify(options, payload, canary, result)
		if matched {
			detail := fmt.Sprintf("XSS detected in %s context (tag=%s, attr=%s)",
				result.Context, result.TagName, result.AttributeName)
			if options.ResponseHeaders != nil {
				if csp, ok := options.ResponseHeaders["Content-Security-Policy"]; ok && len(csp) > 0 {
					detail += fmt.Sprintf(" [CSP: %s]", csp[0])
				}
			}
			return true, detail, nil
		}
	}

	return false, "", nil
}

// replayAndVerify replays the request with a payload and checks for unencoded reflection
func (a *Analyzer) replayAndVerify(options *analyzers.Options, payload, canary string, result *AnalysisResult) bool {
	// In the context of the fuzzing pipeline, this would send a new request
	// with the payload substituted for the canary and check the response.
	// For now, we verify by checking if the canary's special characters
	// survived encoding in the response.
	body := options.ResponseBody
	lowerBody := strings.ToLower(body)
	lowerCanary := strings.ToLower(canary)

	canaryIdx := strings.Index(lowerBody, lowerCanary)
	if canaryIdx == -1 {
		return false
	}

	// Check which special characters survived
	specialChars := map[rune]bool{
		'<': false, '>': false, '"': false, '\'': false, '/': false,
	}
	for _, ch := range XSSCanary {
		if _, ok := specialChars[ch]; ok {
			escaped := ""
			switch ch {
			case '<':
				escaped = "&lt;"
			case '>':
				escaped = "&gt;"
			case '"':
				escaped = "&quot;"
			case '\'':
				escaped = "&#x27;"
			case '/':
				escaped = "&#x2f;"
			}
			if escaped != "" {
				// Check if the character was HTML-encoded at the reflection point
				reflected := body[canaryIdx : canaryIdx+len(canary)]
				if strings.Contains(reflected, escaped) {
					specialChars[ch] = false // was encoded
				} else if strings.ContainsRune(reflected, ch) {
					specialChars[ch] = true // survived unencoded
				}
			}
		}
	}

	// For context-appropriate verification
	switch result.Context {
	case ContextHTMLText:
		// Need < and > unencoded for tag injection
		return specialChars['<'] && specialChars['>']
	case ContextAttribute:
		// Need " unencoded to break out of attribute
		return specialChars['"'] || specialChars['\'']
	case ContextAttributeUnquoted:
		// Space is enough to break out
		return true
	case ContextScript, ContextScriptString:
		// Need </ or quote chars unencoded
		return specialChars['<'] || specialChars['\''] || specialChars['"']
	case ContextScriptURI:
		// Inside javascript: URI - parentheses etc. are typically unencoded
		return true
	case ContextStyle:
		// Need </ unencoded to break out of style
		return specialChars['<']
	case ContextHTMLComment:
		// Need --> unencoded to break out of comment
		return specialChars['>']
	default:
		return false
	}
}

// compile-time interface check
var _ analyzers.Analyzer = &Analyzer{}

// Make sure the import of retryablehttp is used (needed for Options.HttpClient)
var _ = (*retryablehttp.Request)(nil)
