package xss

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

// Analyzer detects XSS vulnerabilities by analyzing the HTML context where input is reflected
type Analyzer struct{}

var _ analyzers.Analyzer = &Analyzer{}

const (
	analyzerName        = "xss_context"
	canaryPlaceholder   = "[XSS_CANARY]"
	canaryPrefix        = "Nucl3i"
	canaryRandomLen     = 6
	canarySpecialChars  = "<>'\""
	canarySpecialLen    = 4 // len(canarySpecialChars)
	canaryTotalLen      = len(canaryPrefix) + canaryRandomLen + canarySpecialLen
	maxResponseBodySize = 10 * 1024 * 1024 // 10MB limit
	maxContextsToTry    = 3                // Maximum number of contexts to attempt exploitation
)

func init() {
	analyzers.RegisterAnalyzer(analyzerName, &Analyzer{})
}

// Name returns the name of the analyzer
func (a *Analyzer) Name() string {
	return analyzerName
}

// ApplyInitialTransformation replaces [XSS_CANARY] with a special probe string
// The probe contains XSS-critical chars (<>'") so we can detect which ones get filtered
func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	// Create a unique probe with special chars to test what gets through
	smartCanary := generateSmartCanary()
	data = strings.ReplaceAll(data, canaryPlaceholder, smartCanary)

	// Replace other placeholders like [RANDNUM]
	data = analyzers.ApplyPayloadTransformations(data)

	return data
}

// generateSmartCanary creates a unique canary with embedded special chars
// Format: "Nucl3iXXXXXX<>'\""  where XXXXXX is random
func generateSmartCanary() string {
	randStr := randStringBytesMask(canaryRandomLen)
	// Include critical XSS characters for filter detection
	return fmt.Sprintf("%s%s%s", canaryPrefix, randStr, canarySpecialChars)
}

// randStringBytesMask generates a random alphanumeric string of length n
func randStringBytesMask(n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letterBytes))))
		if err != nil {
			// If random generation fails, just use 'a' - extremely rare but good to handle
			b[i] = letterBytes[0]
			continue
		}
		b[i] = letterBytes[num.Int64()]
	}
	return string(b)
}

// Analyze is the main entry point for XSS detection
// Strategy: send a probe first, see where it shows up, then send a targeted exploit
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	// Pull out the canary from the payload we built earlier
	smartCanary := extractCanaryFromPayload(options.FuzzGenerated.Value)
	if smartCanary == "" {
		return false, "", fmt.Errorf("no XSS canary found in payload")
	}

	// STEP 1: Send the probe request
	gr := options.FuzzGenerated

	// ApplyInitialTransformation already put the canary in, so just rebuild and send
	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return false, "", fmt.Errorf("could not rebuild request: %w", err)
	}

	gologger.Verbose().Msgf("[%s] Sending probe with smart canary: %s", a.Name(), smartCanary)

	// Send the probe request
	resp, err := options.HttpClient.Do(rebuilt)
	if err != nil {
		return false, "", fmt.Errorf("could not send probe request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body with limit
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return false, "", fmt.Errorf("could not read response body: %w", err)
	}
	responseBody := string(bodyBytes)

	// Check if canary is reflected in the response
	baseCanary := extractBaseCanary(smartCanary)
	if !strings.Contains(responseBody, baseCanary) {
		gologger.Verbose().Msgf("[%s] Canary not reflected in response", a.Name())
		return false, "", nil
	}

	gologger.Verbose().Msgf("[%s] Canary reflected! Analyzing contexts...", a.Name())

	// STEP 2: Use HTML tokenizer to find where the probe appeared and what context it's in
	contexts := DetectContextsRobust(responseBody, smartCanary)

	if len(contexts) == 0 {
		// Early exit: probe was reflected but all dangerous chars were encoded
		gologger.Verbose().Msgf("[%s] All reflections are unexploitable (filtered)", a.Name())
		return false, "", nil
	}

	// Contexts are already sorted by how easy they are to exploit
	// Try up to maxContextsToTry contexts, starting with the most exploitable
	for i := 0; i < len(contexts) && i < maxContextsToTry; i++ {
		ctx := contexts[i]

		if i == 0 {
			gologger.Verbose().Msgf("[%s] Most exploitable context: %s (rank %d)", a.Name(),
				ctx.Type.String(), ctx.Type.ExploitabilityRank())
		} else {
			gologger.Verbose().Msgf("[%s] Trying fallback context: %s", a.Name(), ctx.Type.String())
		}

		// Select the best payload for this context
		payload := SelectPayload(ctx)
		if payload == nil {
			gologger.Verbose().Msgf("[%s] No viable payload found for context %s", a.Name(), ctx.Type.String())
			continue
		}

		gologger.Verbose().Msgf("[%s] Selected payload: %s", a.Name(), payload.Description)

		// Send the targeted payload
		matched, matchReason, err := a.sendTargetedPayload(options, payload, ctx)
		if err != nil {
			return false, "", err
		}

		if matched {
			return true, matchReason, nil
		}
	}

	return false, "", nil
}

// sendTargetedPayload sends a payload and verifies if XSS was successful
func (a *Analyzer) sendTargetedPayload(options *analyzers.Options, payload *XSSPayload, ctx ReflectionContext) (bool, string, error) {
	gr := options.FuzzGenerated

	// Transform payload (replace [RANDNUM] and other placeholders)
	transformedPayload := analyzers.ApplyPayloadTransformations(payload.Value)

	// Set the payload value in the component
	if err := gr.Component.SetValue(gr.Key, transformedPayload); err != nil {
		return false, "", fmt.Errorf("could not set payload value in component: %w", err)
	}

	// Rebuild the request with the payload
	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return false, "", fmt.Errorf("could not rebuild request: %w", err)
	}

	gologger.Verbose().Msgf("[%s] Sending payload: %s", a.Name(), payload.Value)

	// Send the request
	resp, err := options.HttpClient.Do(rebuilt)
	if err != nil {
		return false, "", fmt.Errorf("could not send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body with limit
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return false, "", fmt.Errorf("could not read response body: %w", err)
	}
	respBody := string(bodyBytes)

	// Verify that the payload was executed
	if VerifyPayloadExecution(respBody, payload.VerificationPattern) {
		matchReason := fmt.Sprintf("XSS in %s context via %s", ctx.Type.String(), payload.Description)
		gologger.Info().Msgf("[%s] ✓ %s", a.Name(), matchReason)
		return true, matchReason, nil
	}

	gologger.Verbose().Msgf("[%s] Payload not executed in response", a.Name())
	return false, "", nil
}

// extractCanaryFromPayload extracts the smart canary from the payload
// Returns empty string if canary is not found or is truncated
func extractCanaryFromPayload(payload string) string {
	// Find the start of the canary
	start := strings.Index(payload, canaryPrefix)
	if start == -1 {
		return ""
	}

	// Calculate expected end position
	// Format: Nucl3iXXXXXX<>'"
	end := start + canaryTotalLen
	if end > len(payload) {
		// Payload is truncated, cannot extract valid canary
		return ""
	}

	return payload[start:end]
}
