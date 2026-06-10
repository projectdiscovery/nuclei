// Package redirect implements an open-redirect analyzer for the fuzzer.
//
// It injects a unique, non-resolvable canary host using several open-redirect
// payload styles (absolute, scheme-relative, backslash tricks) and confirms a
// hit when the response redirects to that canary host — either via the Location
// header (redirects disabled, the nuclei default) or via the final request URL
// (redirects followed). The canary host is random and unresolvable, so a match
// is unambiguous and no real third-party traffic leaves the scanner.
package redirect

import (
	"net/url"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

const analyzerName = "open_redirect"

// Analyzer implements the analyzers.Analyzer interface for open redirects.
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

// GenerateProbes builds open-redirect payloads pointing at canaryHost. It is
// exported and pure for unit-testing without a network.
func GenerateProbes(canaryHost string) []string {
	return []string{
		"https://" + canaryHost + "/",
		"//" + canaryHost + "/",
		"https:////" + canaryHost + "/",
		"/\\" + canaryHost + "/",
		"https:/" + canaryHost + "/",
		"https://" + canaryHost + "%2f%2e%2e",
	}
}

// RedirectsToCanary reports whether either the Location header or the final
// request host points at canaryHost. Backslashes are normalized to forward
// slashes because browsers treat "/\host" as "//host". It is exported and pure
// for testability.
func RedirectsToCanary(locationHeader, finalHost, canaryHost string) bool {
	if canaryHost == "" {
		return false
	}
	if finalHost != "" && strings.EqualFold(finalHost, canaryHost) {
		return true
	}
	if locationHeader == "" {
		return false
	}
	normalized := strings.ReplaceAll(locationHeader, "\\", "/")
	if u, err := url.Parse(normalized); err == nil {
		if strings.EqualFold(u.Hostname(), canaryHost) {
			return true
		}
	}
	return false
}

// Analyze injects open-redirect payloads and reports whether the target
// redirects to the canary host.
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	if options == nil || options.FuzzGenerated.Component == nil || options.HttpClient == nil {
		return false, "", nil
	}
	gr := options.FuzzGenerated
	canaryHost := randomCanaryHost()

	defer func() {
		_ = gr.Component.SetValue(gr.Key, gr.OriginalValue)
	}()

	for _, payload := range GenerateProbes(canaryHost) {
		rebuilt, err := analyzers.SetValueAndRebuild(gr, payload)
		if err != nil {
			return false, "", err
		}
		options.RateLimit()
		resp, err := options.HttpClient.Do(rebuilt)
		if err != nil {
			// A transport error is expected when redirects are followed to the
			// unresolvable canary host; skip this probe rather than aborting.
			continue
		}
		location := resp.Header.Get("Location")
		finalHost := ""
		if resp.Request != nil && resp.Request.URL != nil {
			finalHost = resp.Request.URL.Hostname()
		}
		_ = resp.Body.Close()

		if RedirectsToCanary(location, finalHost, canaryHost) {
			return true, "open redirect: target redirected to canary host via payload " + payload, nil
		}
	}
	return false, "", nil
}

// randomCanaryHost returns a random, syntactically valid but non-resolvable
// host under a reserved-looking label so it never collides with real hosts and
// never generates real third-party traffic.
func randomCanaryHost() string {
	return analyzers.RandToken(12) + ".nucleicanary.invalid"
}
