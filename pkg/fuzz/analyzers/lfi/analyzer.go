// Package lfi implements a local file inclusion / path traversal analyzer for
// the fuzzer.
//
// It injects a set of traversal payloads targeting well-known files
// (/etc/passwd on *nix, win.ini on Windows) and confirms a hit only when the
// response contains a content signature unique to those files. Matching the
// actual file contents (e.g. the root: line of /etc/passwd) is a strong,
// low-false-positive signal of arbitrary file read.
package lfi

import (
	"regexp"
	"strconv"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

const analyzerName = "lfi"

// Analyzer implements the analyzers.Analyzer interface for LFI/path traversal.
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

// traversalPayloads target /etc/passwd and Windows win.ini using a mix of plain
// traversal, nested ("....//") bypasses, URL-encoding and absolute paths.
var traversalPayloads = []string{
	"../../../../../../../../etc/passwd",
	"....//....//....//....//....//etc/passwd",
	"..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
	"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	"/etc/passwd",
	"file:///etc/passwd",
	"..\\..\\..\\..\\..\\..\\windows\\win.ini",
	"..%5c..%5c..%5c..%5cwindows%5cwin.ini",
	"C:\\windows\\win.ini",
}

// fileSignature pairs a target file with a regex that matches content unique
// to that file.
type fileSignature struct {
	File  string
	Regex *regexp.Regexp
}

var fileSignatures = []fileSignature{
	// /etc/passwd: entries like "root:x:0:0:root:/root:/bin/bash". We require a
	// well-known system account name (root, daemon, nobody, ...) followed by the
	// full 7-field name:passwd:uid:gid:gecos:home:shell structure. Requiring a
	// known account — rather than any token — keeps false positives low against
	// arbitrary colon-delimited content (config/CSV dumps) while staying
	// unanchored so it still matches when the file is wrapped (e.g. in <pre>).
	{"/etc/passwd", regexp.MustCompile(`(?i)\b(root|daemon|bin|sys|sync|games|man|lp|mail|news|nobody|www-data|sshd|ftp):[^:\r\n]*:\d+:\d+:[^:\r\n]*:[^:\r\n]*:[^:\r\n]*`)},
	// Windows win.ini: the [fonts]/[extensions] sections
	{"win.ini", regexp.MustCompile(`(?i)\[(fonts|extensions|mci extensions|files)\]`)},
	{"win.ini", regexp.MustCompile(`(?i)for 16-bit app support`)},
}

// MatchFileSignature returns the target file whose content signature appears in
// body, if any. It is exported and pure for unit-testing without a network.
func MatchFileSignature(body string) (string, bool) {
	if body == "" {
		return "", false
	}
	for _, sig := range fileSignatures {
		if sig.Regex.MatchString(body) {
			return sig.File, true
		}
	}
	return "", false
}

// Analyze injects traversal payloads and reports LFI when a target file's
// content signature appears in a response but not in the baseline.
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	if options == nil || options.FuzzGenerated.Component == nil || options.HttpClient == nil {
		return false, "", nil
	}
	gr := options.FuzzGenerated

	defer func() {
		_ = gr.Component.SetValue(gr.Key, gr.OriginalValue)
	}()

	// Baseline: if the file signature is already present with the original
	// value, a later match proves nothing, so bail to avoid false positives.
	baselineBody, err := analyzers.SendValueAndReadBody(options, gr.OriginalValue)
	if err != nil {
		return false, "", err
	}
	if _, matched := MatchFileSignature(baselineBody); matched {
		return false, "", nil
	}

	for _, payload := range traversalPayloads {
		body, err := analyzers.SendValueAndReadBody(options, payload)
		if err != nil {
			// A single failed probe (timeout, reset) must not abort the whole
			// analysis; the remaining payloads may still surface the bug.
			continue
		}
		if file, matched := MatchFileSignature(body); matched {
			return true, "lfi: contents of " + file + " disclosed via payload " + strconv.Quote(payload), nil
		}
	}
	return false, "", nil
}
