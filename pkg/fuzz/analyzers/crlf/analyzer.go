// Package crlf implements a CRLF-injection / HTTP response-splitting analyzer
// for the fuzzer.
//
// It injects carriage-return/line-feed sequences followed by a uniquely named
// canary header (and a canary Set-Cookie) and confirms a hit only when that
// exact header/cookie appears in the response. Because the header name and
// value are random, a match means user input broke out of its context into the
// response header section — a true CRLF injection with no baseline needed.
//
// Payloads use raw CR/LF characters (not pre-encoded "%0d%0a"). The request
// rebuild percent-encodes URL/query components exactly once, so the server
// receives a single layer of encoding; pre-encoding here would double-encode.
package crlf

import (
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

const analyzerName = "crlf"

// Analyzer implements the analyzers.Analyzer interface for CRLF injection.
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

// GenerateProbes builds CRLF payloads that attempt to inject headerName/value
// and a Set-Cookie carrying value. It is exported and pure for testability.
func GenerateProbes(headerName, value string) []string {
	hdr := headerName + ": " + value
	cookie := "Set-Cookie: crlf=" + value
	return []string{
		"\r\n" + hdr,
		"\r\n\r\n" + hdr,
		"\n" + hdr,
		"\r" + hdr,
		"\r\n" + cookie,
		// trailing comment/space variants seen in real-world bypasses
		" \r\n" + hdr,
	}
}

// DetectInjection reports whether the canary header (name/value) or a
// Set-Cookie carrying value is present in the response headers. It is exported
// and pure so it can be unit-tested without a network.
func DetectInjection(h http.Header, headerName, value string) bool {
	if h == nil || headerName == "" || value == "" {
		return false
	}
	if strings.TrimSpace(h.Get(headerName)) == value {
		return true
	}
	for _, c := range h.Values("Set-Cookie") {
		if strings.Contains(c, value) {
			return true
		}
	}
	return false
}

// Analyze injects CRLF payloads and reports whether the canary header or cookie
// surfaced in the response headers.
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	if options == nil || options.FuzzGenerated.Component == nil || options.HttpClient == nil {
		return false, "", nil
	}
	gr := options.FuzzGenerated
	headerName := "X-Crlf-" + randomToken()
	value := randomToken()

	defer func() {
		_ = gr.Component.SetValue(gr.Key, gr.OriginalValue)
	}()

	for _, payload := range GenerateProbes(headerName, value) {
		// keep the original value so server-side processing still runs, then
		// append the breakout payload.
		rebuilt, err := analyzers.SetValueAndRebuild(gr, gr.OriginalValue+payload)
		if err != nil {
			// some components (e.g. headers) reject raw CR/LF at build time;
			// skip rather than aborting the whole analysis.
			continue
		}
		resp, err := options.HttpClient.Do(rebuilt)
		if err != nil {
			continue
		}
		hit := DetectInjection(resp.Header, headerName, value)
		_ = resp.Body.Close()
		if hit {
			return true, "crlf: injected response header surfaced via payload " + strconv.Quote(payload), nil
		}
	}
	return false, "", nil
}

var (
	tokenRandMu sync.Mutex
	tokenRand   = rand.New(rand.NewSource(time.Now().UnixNano()))
)

const tokenLetters = "abcdefghijklmnopqrstuvwxyz0123456789"

func randomToken() string {
	const n = 10
	b := make([]byte, n)
	tokenRandMu.Lock()
	for i := range b {
		b[i] = tokenLetters[tokenRand.Intn(len(tokenLetters))]
	}
	tokenRandMu.Unlock()
	return string(b)
}
