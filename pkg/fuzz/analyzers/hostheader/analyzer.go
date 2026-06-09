// Package hostheader implements a host-header injection analyzer for the
// fuzzer.
//
// It replays the request with a random canary host placed in the Host header
// and in the common host-override headers (X-Forwarded-Host, etc.) and flags an
// issue when that canary host is reflected back into the response — in the
// Location header or as the host of an absolute URL in the body. This is the
// primitive behind password-reset poisoning and web-cache poisoning. The canary
// host is random, so any reflection is unambiguous and needs no baseline.
package hostheader

import (
	"math/rand"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

const analyzerName = "host_header_injection"

// Analyzer implements the analyzers.Analyzer interface for host-header injection.
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

// overrideHeaders are the headers (besides Host itself) commonly trusted by
// applications/proxies to derive the effective host.
var overrideHeaders = []string{
	"X-Forwarded-Host",
	"X-Host",
	"X-Forwarded-Server",
	"X-HTTP-Host-Override",
	"Forwarded",
}

// ReflectsCanary reports whether the canary host appears as the host of the
// Location header or of an absolute URL in the body. It is exported and pure so
// it can be unit-tested without a network.
func ReflectsCanary(body, locationHeader, canaryHost string) bool {
	if canaryHost == "" {
		return false
	}
	if locationHeader != "" {
		if u, err := url.Parse(locationHeader); err == nil && strings.EqualFold(u.Hostname(), canaryHost) {
			return true
		}
	}
	if body == "" {
		return false
	}
	// match the canary only when it appears as a URL host (scheme-relative or
	// absolute), not as an arbitrary substring, to avoid accidental matches.
	lc := strings.ToLower(body)
	cl := strings.ToLower(canaryHost)
	return strings.Contains(lc, "//"+cl) ||
		strings.Contains(lc, "://"+cl) ||
		strings.Contains(lc, "@"+cl)
}

// Analyze replays the request with canary host overrides and reports reflection.
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	if options == nil || options.FuzzGenerated.Component == nil || options.HttpClient == nil {
		return false, "", nil
	}
	gr := options.FuzzGenerated
	canary := randomCanaryHost()

	defer func() {
		_ = gr.Component.SetValue(gr.Key, gr.OriginalValue)
	}()

	// Probe each override header individually, plus a direct Host override.
	probes := append([]string{"Host"}, overrideHeaders...)
	for _, header := range probes {
		rebuilt, err := analyzers.SetValueAndRebuild(gr, gr.OriginalValue)
		if err != nil {
			return false, "", err
		}
		if header == "Host" {
			rebuilt.Host = canary
		} else {
			rebuilt.Header.Set(header, canary)
		}

		resp, body, err := analyzers.DoAndReadBody(options.HttpClient, rebuilt)
		if err != nil {
			continue
		}
		location := resp.Header.Get("Location")
		if ReflectsCanary(body, location, canary) {
			return true, "host header injection: canary host reflected via " + header + " header", nil
		}
	}
	return false, "", nil
}

var (
	canaryRandMu sync.Mutex
	canaryRand   = rand.New(rand.NewSource(time.Now().UnixNano()))
)

const canaryLetters = "abcdefghijklmnopqrstuvwxyz0123456789"

func randomCanaryHost() string {
	const n = 12
	b := make([]byte, n)
	canaryRandMu.Lock()
	for i := range b {
		b[i] = canaryLetters[canaryRand.Intn(len(canaryLetters))]
	}
	canaryRandMu.Unlock()
	return string(b) + ".hostcanary.example"
}
