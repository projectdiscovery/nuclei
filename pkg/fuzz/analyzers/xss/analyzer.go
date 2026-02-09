package xss

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

type Analyzer struct{}

var _ analyzers.Analyzer = &Analyzer{}

func init() {
	analyzers.RegisterAnalyzer("xss_context", &Analyzer{})
}

func (a *Analyzer) Name() string {
	return "xss_context"
}

func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	data = analyzers.ApplyPayloadTransformations(data)
	if strings.Contains(data, "[XSS_MARKER]") {
		marker := "nuclei" + analyzers.RandStringBytesMask(8)
		data = strings.ReplaceAll(data, "[XSS_MARKER]", marker)
		params["xss_marker"] = marker
	}
	return data
}

func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	if options.ResponseBody == "" {
		return false, "", nil
	}
	reflectedValue := ""
	if options.AnalyzerParameters != nil {
		if marker, ok := options.AnalyzerParameters["xss_marker"].(string); ok {
			reflectedValue = marker
		}
	}
	if reflectedValue == "" {
		reflectedValue = options.FuzzGenerated.Value
	}
	if reflectedValue == "" {
		return false, "", nil
	}
	ctx := DetectContext(options.ResponseBody, reflectedValue)
	if ctx == ContextNone {
		return false, "", nil
	}
	detail := fmt.Sprintf(
		"[xss_context] reflection detected in %s context for parameter '%s'",
		ctx.String(),
		options.FuzzGenerated.Parameter,
	)
	return true, detail, nil
}
