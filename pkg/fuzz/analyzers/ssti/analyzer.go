// Package ssti implements a server-side template injection (SSTI) analyzer for
// the fuzzer. It uses a randomized arithmetic oracle: it injects a multiplication
// expression in a number of common template-engine syntaxes, wrapped in unique
// random sentinels, and confirms injection only when the template engine
// evaluates the expression (i.e. the product appears between the sentinels).
//
// This arithmetic-evaluation approach yields very low false positives: a plain
// reflection of the payload leaves the literal expression (e.g. "${7*7}")
// between the sentinels, which never matches the product ("49"). A match
// therefore means the server actually evaluated the expression — a strong SSTI
// signal that frequently escalates to RCE.
package ssti

import (
	"io"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

const (
	analyzerName         = "ssti"
	maxResponseBodyBytes = 10 * 1024 * 1024 // 10 MiB
)

// Analyzer implements the analyzers.Analyzer interface for SSTI detection.
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

// Probe is a single SSTI payload for a family of template engines.
type Probe struct {
	// Engine names the template engine families this syntax targets.
	Engine string
	// Payload is the value to inject (sentinels + expression).
	Payload string
}

// Analyze injects arithmetic SSTI probes and reports whether any template engine
// evaluated the expression.
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	if options == nil || options.FuzzGenerated.Component == nil || options.HttpClient == nil {
		return false, "", nil
	}
	gr := options.FuzzGenerated

	first := analyzers.GetRandomInteger()
	second := analyzers.GetRandomInteger()
	product := first * second
	startToken := randToken()
	endToken := randToken()

	probes := GenerateProbes(first, second, startToken, endToken)

	// Always restore the original value once we are done probing.
	defer func() {
		_ = gr.Component.SetValue(gr.Key, gr.OriginalValue)
	}()

	for _, probe := range probes {
		if err := gr.Component.SetValue(gr.Key, probe.Payload); err != nil {
			return false, "", err
		}
		rebuilt, err := gr.Component.Rebuild()
		if err != nil {
			return false, "", err
		}
		resp, err := options.HttpClient.Do(rebuilt)
		if err != nil {
			return false, "", err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
		_ = resp.Body.Close()
		if err != nil {
			return false, "", err
		}

		if DetectEvaluation(string(body), startToken, endToken, product) {
			return true, "ssti: expression evaluated by " + probe.Engine + " (got " + strconv.Itoa(product) + ")", nil
		}
	}
	return false, "", nil
}

// GenerateProbes builds the SSTI payloads for a*b across common template-engine
// syntaxes, each wrapped in the given sentinels. It is exported and pure so it
// can be unit-tested without any network access.
func GenerateProbes(a, b int, startToken, endToken string) []Probe {
	as := strconv.Itoa(a)
	bs := strconv.Itoa(b)
	expr := as + "*" + bs

	wrap := func(payload string) string {
		return startToken + payload + endToken
	}

	return []Probe{
		{Engine: "EL/SpEL/JSP-EL/Mako/Freemarker", Payload: wrap("${" + expr + "}")},
		{Engine: "Jinja2/Twig/Nunjucks/Angular", Payload: wrap("{{" + expr + "}}")},
		{Engine: "Ruby ERB/Thymeleaf/JSF", Payload: wrap("#{" + expr + "}")},
		{Engine: "Thymeleaf", Payload: wrap("*{" + expr + "}")},
		{Engine: "Razor", Payload: wrap("@(" + expr + ")")},
		{Engine: "ERB/ASP", Payload: wrap("<%= " + expr + " %>")},
		{Engine: "Velocity", Payload: wrap("#set($p=" + expr + ")${p}")},
		{Engine: "Smarty/generic", Payload: wrap("{" + expr + "}")},
	}
}

// DetectEvaluation reports whether the response body contains the evaluated
// product between the two sentinels, which indicates the template engine
// executed the injected expression. It is exported and pure for testability.
func DetectEvaluation(body, startToken, endToken string, product int) bool {
	if body == "" || startToken == "" || endToken == "" {
		return false
	}
	needle := startToken + strconv.Itoa(product) + endToken
	return strings.Contains(body, needle)
}

var (
	tokenRandMu sync.Mutex
	tokenRand   = rand.New(rand.NewSource(time.Now().UnixNano()))
)

const tokenLetters = "abcdefghijklmnopqrstuvwxyz"

// randToken returns a short random lowercase alphabetic sentinel. Alphabetic
// (never numeric) so it cannot be confused with the arithmetic product.
func randToken() string {
	const n = 6
	b := make([]byte, n)
	tokenRandMu.Lock()
	for i := range b {
		b[i] = tokenLetters[tokenRand.Intn(len(tokenLetters))]
	}
	tokenRandMu.Unlock()
	return "s" + string(b)
}
