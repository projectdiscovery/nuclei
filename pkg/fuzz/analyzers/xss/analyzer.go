package xss

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

// Analyzer is an XSS context analyzer for the fuzzer
type Analyzer struct{}

var _ analyzers.Analyzer = &Analyzer{}

func init() {
	analyzers.RegisterAnalyzer("xss_context", &Analyzer{})
}

// Name returns the name of the analyzer
func (a *Analyzer) Name() string {
	return "xss_context"
}

// ApplyInitialTransformation applies the transformation to the initial payload
// Replaces [XSS_CANARY] with a unique probe containing XSS-critical characters
// This enables filter detection by observing which characters survive reflection
func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	// Generate smart canary with embedded special characters
	smartCanary := generateSmartCanary()
	data = strings.ReplaceAll(data, "[XSS_CANARY]", smartCanary)

	// Apply standard payload transformations ([RANDNUM], [RANDSTR], etc.)
	data = analyzers.ApplyPayloadTransformations(data)

	return data
}

// generateSmartCanary creates a unique canary with embedded special chars
// Format: "Nucl3iXXXXXX<>'\""  where XXXXXX is random
func generateSmartCanary() string {
	randStr := randStringBytesMask(6)
	// Include critical XSS characters for filter detection
	return fmt.Sprintf("Nucl3i%s<>'\"", randStr)
}

// randStringBytesMask generates a random alphanumeric string of length n
func randStringBytesMask(n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letterBytes))))
		b[i] = letterBytes[num.Int64()]
	}
	return string(b)
}

// Analyze is the main analysis function that orchestrates the XSS detection
// Uses intelligent probe analysis for filter detection, context classification, and targeted exploitation
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	// Extract the smart canary from the original payload
	smartCanary := extractCanaryFromPayload(options.FuzzGenerated.OriginalPayload)
	if smartCanary == "" {
		return false, "", errors.New("no XSS canary found in payload")
	}

	// REQUEST 1: Send the probe request with smart canary
	gr := options.FuzzGenerated

	// The payload has already been transformed with the smart canary
	// by ApplyInitialTransformation, so we just need to send it
	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return false, "", errors.Wrap(err, "could not rebuild request")
	}

	gologger.Verbose().Msgf("[%s] Sending probe with smart canary: %s", a.Name(), smartCanary)

	// Send the probe request
	resp, err := options.HttpClient.Do(rebuilt)
	if err != nil {
		return false, "", errors.Wrap(err, "could not send probe request")
	}

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return false, "", errors.Wrap(err, "could not read response body")
	}
	responseBody := string(bodyBytes)

	// Check if canary is reflected in the response
	baseCanary := extractBaseCanary(smartCanary)
	if !strings.Contains(responseBody, baseCanary) {
		gologger.Verbose().Msgf("[%s] Canary not reflected in response", a.Name())
		return false, "", nil
	}

	gologger.Verbose().Msgf("[%s] Canary reflected! Analyzing contexts...", a.Name())

	// Use HTML tokenizer to detect all reflection contexts and analyze filters
	contexts := DetectContextsRobust(responseBody, smartCanary)

	if len(contexts) == 0 {
		// Optimization: All reflections were filtered or unexploitable
		gologger.Verbose().Msgf("[%s] All reflections are unexploitable (filtered)", a.Name())
		return false, "", nil
	}

	// Contexts are sorted by exploitability rank (easiest first)
	mostExploitableCtx := contexts[0]
	gologger.Verbose().Msgf("[%s] Most exploitable context: %s (rank %d)", a.Name(),
		mostExploitableCtx.Type.String(), mostExploitableCtx.Type.ExploitabilityRank())

	// Select the best payload for this context
	payload := SelectPayload(mostExploitableCtx)
	if payload == nil {
		gologger.Verbose().Msgf("[%s] No viable payload found for context %s", a.Name(), mostExploitableCtx.Type.String())
		return false, "", nil
	}

	gologger.Verbose().Msgf("[%s] Selected payload: %s", a.Name(), payload.Description)

	// REQUEST 2: Send the targeted payload
	matched, matchReason, err := a.sendTargetedPayload(options, payload, mostExploitableCtx)
	if err != nil {
		return false, "", err
	}

	if matched {
		return true, matchReason, nil
	}

	// If first context didn't work, try other exploitable contexts
	for i := 1; i < len(contexts) && i < 3; i++ {
		ctx := contexts[i]
		payload = SelectPayload(ctx)
		if payload == nil {
			continue
		}

		gologger.Verbose().Msgf("[%s] Trying fallback context: %s", a.Name(), ctx.Type.String())
		matched, matchReason, err = a.sendTargetedPayload(options, payload, ctx)
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

	// Set the payload value in the component
	if err := gr.Component.SetValue(gr.Key, payload.Value); err != nil {
		return false, "", errors.Wrap(err, "could not set payload value in component")
	}

	// Rebuild the request with the payload
	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return false, "", errors.Wrap(err, "could not rebuild request")
	}

	gologger.Verbose().Msgf("[%s] Sending payload: %s", a.Name(), payload.Value)

	// Send the request
	resp, err := options.HttpClient.Do(rebuilt)
	if err != nil {
		return false, "", errors.Wrap(err, "could not send request")
	}

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return false, "", errors.Wrap(err, "could not read response body")
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

// extractCanaryFromPayload extracts the smart canary from the original payload
func extractCanaryFromPayload(payload string) string {
	// Look for the pattern "Nucl3i" followed by chars and special chars
	if !strings.Contains(payload, "Nucl3i") {
		return ""
	}

	// Find the start of the canary
	start := strings.Index(payload, "Nucl3i")
	if start == -1 {
		return ""
	}

	// Extract canary (should include special chars at the end)
	// Format: Nucl3iXXXXXX<>'\"
	end := start + len("Nucl3i") + 6 + 4 // 6 random chars + 4 special chars (<>'")
	if end > len(payload) {
		end = len(payload)
	}

	return payload[start:end]
}
