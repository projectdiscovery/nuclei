// Package cmdi implements an in-band OS command injection analyzer for the
// fuzzer.
//
// It appends a set of shell command separators followed by the "id" command and
// confirms a hit only when the response contains the unmistakable
// "uid=...(...) gid=...(...)" output of a real id execution. Matching actual
// command output (rather than payload reflection) is an extremely strong,
// low-false-positive RCE signal. Blind command injection is covered by the
// time-based analyzer; this one targets the in-band case where output is
// reflected.
package cmdi

import (
	"io"
	"regexp"
	"strconv"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

const (
	analyzerName         = "cmdi"
	maxResponseBodyBytes = 10 * 1024 * 1024 // 10 MiB
)

// Analyzer implements the analyzers.Analyzer interface for OS command injection.
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

// commandSeparators break out of the surrounding shell context in different
// ways (sequencing, piping, substitution, newline). Each is suffixed with "id".
var commandSeparators = []string{
	";id",
	"|id",
	"||id",
	"&&id",
	"&id",
	"`id`",
	"$(id)",
	"\nid",
	";id;",
	"|id #",
}

// reIDOutput matches the output of the unix "id" command, e.g.
// "uid=0(root) gid=0(root) groups=0(root)".
var reIDOutput = regexp.MustCompile(`uid=\d+\([0-9A-Za-z_.\-$]+\)\s+gid=\d+\([0-9A-Za-z_.\-$]+\)`)

// MatchCommandOutput reports whether the body contains "id" command output. It
// is exported and pure for unit-testing without a network.
func MatchCommandOutput(body string) bool {
	if body == "" {
		return false
	}
	return reIDOutput.MatchString(body)
}

// Analyze appends command-injection payloads and reports a hit when id command
// output appears in a response but not in the baseline.
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	if options == nil || options.FuzzGenerated.Component == nil || options.HttpClient == nil {
		return false, "", nil
	}
	gr := options.FuzzGenerated

	defer func() {
		_ = gr.Component.SetValue(gr.Key, gr.OriginalValue)
	}()

	baselineBody, err := a.sendAndRead(options, gr.OriginalValue)
	if err != nil {
		return false, "", err
	}
	if MatchCommandOutput(baselineBody) {
		return false, "", nil
	}

	for _, sep := range commandSeparators {
		body, err := a.sendAndRead(options, gr.OriginalValue+sep)
		if err != nil {
			continue
		}
		if MatchCommandOutput(body) {
			return true, "cmdi: id command output observed via payload " + strconv.Quote(sep), nil
		}
	}
	return false, "", nil
}

func (a *Analyzer) sendAndRead(options *analyzers.Options, value string) (string, error) {
	rebuilt, err := analyzers.SetValueAndRebuild(options.FuzzGenerated, value)
	if err != nil {
		return "", err
	}
	resp, err := options.HttpClient.Do(rebuilt)
	if err != nil {
		return "", err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	_ = resp.Body.Close()
	if err != nil {
		return "", err
	}
	return string(body), nil
}
