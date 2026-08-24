package analyzers

import (
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Analyzer is an interface for all the analyzers
// that can be used for the fuzzer
type Analyzer interface {
	// Name returns the name of the analyzer
	Name() string
	// ApplyTransformation applies the transformation to the initial payload.
	ApplyInitialTransformation(data string, params map[string]interface{}) string
	// Analyze is the main function for the analyzer
	Analyze(options *Options) (bool, string, error)
}

// AnalyzerTemplate is the template for the analyzer
type AnalyzerTemplate struct {
	// description: |
	//   Name is the name of the analyzer to use
	// values:
	//   - time_delay
	//   - xss_context
	//   - ssti
	//   - sqli_error
	//   - lfi
	//   - open_redirect
	//   - crlf
	//   - ssrf
	//   - cors
	//   - cmdi
	//   - host_header_injection
	Name string `json:"name" yaml:"name"`
	// description: |
	//   Parameters is the parameters for the analyzer
	//
	//   Parameters are different for each analyzer. For example, you can customize
	//   time_delay analyzer with sleep_duration, time_slope_error_range, etc. Refer
	//   to the docs for each analyzer to get an idea about parameters.
	Parameters map[string]interface{} `json:"parameters" yaml:"parameters"`
}

var (
	analyzers map[string]Analyzer
)

// RegisterAnalyzer registers a new analyzer
func RegisterAnalyzer(name string, analyzer Analyzer) {
	analyzers[name] = analyzer
}

// GetAnalyzer returns the analyzer for a given name
func GetAnalyzer(name string) Analyzer {
	return analyzers[name]
}

func init() {
	analyzers = make(map[string]Analyzer)
}

// Options contains the options for the analyzer
type Options struct {
	FuzzGenerated      fuzz.GeneratedRequest
	HttpClient         *retryablehttp.Client
	ResponseTimeDelay  time.Duration
	AnalyzerParameters map[string]interface{}
	// RateLimitTake, when set, blocks until the scan's global rate limiter
	// permits another request. Each analyzer issues several probes per call, so
	// wiring the same limiter the rest of the scan uses keeps DAST analysis
	// within the user's configured rate budget instead of bursting unthrottled
	// traffic at the target. It is safe to leave nil (e.g. in unit tests).
	RateLimitTake func()
}

// RateLimit blocks until the scan's rate limiter allows another request. It is a
// no-op when no limiter was wired (RateLimitTake is nil), so analyzers can call
// it unconditionally before every probe.
func (o *Options) RateLimit() {
	if o != nil && o.RateLimitTake != nil {
		o.RateLimitTake()
	}
}

// SetValueAndRebuild sets value on the fuzzed component, rebuilds the request,
// and re-applies headers from the original generated request that Rebuild()
// drops. Rebuild() only carries headers present at parse time, so post-parse
// injections (most importantly authentication headers) are lost without this.
// Sharing this keeps every analyzer consistent and authenticated-scan safe.
func SetValueAndRebuild(gr fuzz.GeneratedRequest, value string) (*retryablehttp.Request, error) {
	if err := gr.Component.SetValue(gr.Key, value); err != nil {
		return nil, err
	}
	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return nil, err
	}
	if gr.Request != nil {
		for k, vs := range gr.Request.Header {
			// don't clobber the header we are actively fuzzing
			if gr.Component.Name() == "header" && k == gr.Key {
				continue
			}
			// don't clobber headers the component itself manages on the rebuilt
			// request (e.g. Cookie for the cookie component, Content-Type/Length
			// for the body component); only restore headers that Rebuild dropped
			// (most importantly post-parse auth headers).
			if len(rebuilt.Header.Values(k)) > 0 {
				continue
			}
			rebuilt.Header[k] = vs
		}
	}
	return rebuilt, nil
}

// MaxResponseBodyBytes bounds how much of a response body an analyzer reads so a
// hostile or oversized response cannot exhaust memory.
const MaxResponseBodyBytes = 10 * 1024 * 1024 // 10 MiB

// DoAndReadBody sends req and returns the response along with its body, bounded
// by MaxResponseBodyBytes. The body is fully read and closed before returning,
// so callers may still inspect resp.Header afterwards. resp is nil only when the
// request itself failed.
func DoAndReadBody(client *retryablehttp.Client, req *retryablehttp.Request) (*http.Response, string, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBodyBytes))
	_ = resp.Body.Close()
	if err != nil {
		return resp, "", err
	}
	return resp, string(body), nil
}

// SendValueAndReadBody sets value on the fuzzed component, rebuilds the request
// (restoring auth headers Rebuild drops), sends it, and returns the response
// body. This is the shared path for body-signature analyzers (sqli, cmdi, ssti,
// lfi, ssrf), which only inspect the response body.
func SendValueAndReadBody(options *Options, value string) (string, error) {
	rebuilt, err := SetValueAndRebuild(options.FuzzGenerated, value)
	if err != nil {
		return "", err
	}
	options.RateLimit()
	_, body, err := DoAndReadBody(options.HttpClient, rebuilt)
	return body, err
}

var (
	// randMu guards random: analyzers run concurrently across fuzzed components,
	// and math/rand's top-level source is not safe for concurrent use.
	randMu sync.Mutex
	random = rand.New(rand.NewSource(time.Now().UnixNano()))
)

// ApplyPayloadTransformations applies the payload transformations to the payload
// It supports the below payloads -
//   - [RANDNUM] => random number between 1000 and 9999
//   - [RANDSTR] => random string of 4 characters
func ApplyPayloadTransformations(value string) string {
	randomInt := GetRandomInteger()
	randomStr := randStringBytesMask(4)

	value = strings.ReplaceAll(value, "[RANDNUM]", strconv.Itoa(randomInt))
	value = strings.ReplaceAll(value, "[RANDSTR]", randomStr)
	return value
}

const (
	letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	// alphaNumLower / alphaLower back the shared RandToken / RandAlphaToken
	// helpers used by analyzers for canary hosts, header names and sentinels.
	alphaNumLower = "abcdefghijklmnopqrstuvwxyz0123456789"
	alphaLower    = "abcdefghijklmnopqrstuvwxyz"
)

// randStringFrom returns a random string of length n drawn from alphabet, using
// the shared mutex-guarded source so it is safe for concurrent analyzers.
func randStringFrom(alphabet string, n int) string {
	b := make([]byte, n)
	randMu.Lock()
	for i := range b {
		b[i] = alphabet[random.Intn(len(alphabet))]
	}
	randMu.Unlock()
	return string(b)
}

func randStringBytesMask(n int) string {
	return randStringFrom(letterBytes, n)
}

// RandToken returns a random lowercase alphanumeric token of length n. It suits
// canary hosts/header names and any sentinel that may legitimately be numeric.
func RandToken(n int) string {
	return randStringFrom(alphaNumLower, n)
}

// RandAlphaToken returns a random lowercase alphabetic token of length n (never
// digits), for sentinels that must not be confused with numeric output (e.g.
// the SSTI arithmetic oracle).
func RandAlphaToken(n int) string {
	return randStringFrom(alphaLower, n)
}

// GetRandomInteger returns a random integer between 1000 and 9999
func GetRandomInteger() int {
	randMu.Lock()
	defer randMu.Unlock()
	return random.Intn(9000) + 1000
}
