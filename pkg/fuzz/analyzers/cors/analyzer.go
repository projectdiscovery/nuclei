// Package cors implements a CORS misconfiguration analyzer for the fuzzer.
//
// For the generated request it replays the request with attacker-controlled
// Origin headers (a random canary origin, the "null" origin, and a
// target-suffix origin that defeats naive endsWith checks) and flags a
// misconfiguration when the server reflects that arbitrary origin back in
// Access-Control-Allow-Origin. Reflection together with
// Access-Control-Allow-Credentials: true is reported as the more severe,
// credential-exposing variant.
package cors

import (
	"net/http"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

const analyzerName = "cors"

// Analyzer implements the analyzers.Analyzer interface for CORS misconfig.
type Analyzer struct{}

var _ analyzers.Analyzer = &Analyzer{}

func init() {
	analyzers.RegisterAnalyzer(analyzerName, &Analyzer{})
}

func (a *Analyzer) Name() string {
	return analyzerName
}

func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	return analyzers.ApplyPayloadTransformations(data)
}

// TestOrigins returns the attacker origins to probe. targetHost (may be empty)
// is used to build a suffix-bypass origin. It is exported and pure for testing.
func TestOrigins(targetHost, canaryOrigin string) []string {
	origins := []string{canaryOrigin, "null"}
	if targetHost != "" {
		// "https://<target>.attacker" defeats endsWith(target) checks; the
		// reverse defeats startsWith(target) checks.
		origins = append(origins,
			"https://"+targetHost+".corscanary.example",
			"https://corscanary.example/"+targetHost,
		)
	}
	return origins
}

// AnalyzeCORS reports whether the response reflects sentOrigin in
// Access-Control-Allow-Origin. It is exported and pure for testability.
func AnalyzeCORS(h http.Header, sentOrigin string) (string, bool) {
	if h == nil || sentOrigin == "" {
		return "", false
	}
	acao := strings.TrimSpace(h.Get("Access-Control-Allow-Origin"))
	if acao == "" {
		return "", false
	}
	if !strings.EqualFold(acao, sentOrigin) {
		return "", false
	}
	withCreds := strings.EqualFold(strings.TrimSpace(h.Get("Access-Control-Allow-Credentials")), "true")
	if withCreds {
		return "reflects arbitrary Origin with Access-Control-Allow-Credentials: true", true
	}
	return "reflects arbitrary Origin", true
}

// Analyze replays the request with attacker origins and reports CORS reflection.
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	if options == nil || options.FuzzGenerated.Component == nil || options.HttpClient == nil {
		return false, "", nil
	}
	gr := options.FuzzGenerated

	targetHost := ""
	if gr.Request != nil && gr.Request.URL != nil {
		targetHost = gr.Request.Hostname()
	}
	canary := "https://" + analyzers.RandToken(10) + ".corscanary.example"

	defer func() {
		_ = gr.Component.SetValue(gr.Key, gr.OriginalValue)
	}()

	for _, origin := range TestOrigins(targetHost, canary) {
		// rebuild a benign request (original value) and only vary the Origin
		rebuilt, err := analyzers.SetValueAndRebuild(gr, gr.OriginalValue)
		if err != nil {
			return false, "", err
		}
		rebuilt.Header.Set("Origin", origin)

		options.RateLimit()
		resp, err := options.HttpClient.Do(rebuilt)
		if err != nil {
			continue
		}
		reason, vuln := AnalyzeCORS(resp.Header, origin)
		_ = resp.Body.Close()
		if vuln {
			return true, "cors: " + reason + " (Origin: " + origin + ")", nil
		}
	}
	return false, "", nil
}
