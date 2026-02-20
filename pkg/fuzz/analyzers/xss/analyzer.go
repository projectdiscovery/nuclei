package xss

import (
	"io"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

const analyzerName = "xss_context"

// Analyzer is a first-pass XSS analyzer that validates reflection.
// Context classification is implemented in follow-up steps.
type Analyzer struct{}

var _ analyzers.Analyzer = &Analyzer{}

func init() {
	analyzers.RegisterAnalyzer(analyzerName, &Analyzer{})
}

func (a *Analyzer) Name() string {
	return analyzerName
}

func (a *Analyzer) ApplyInitialTransformation(data string, _ map[string]interface{}) string {
	return analyzers.ApplyPayloadTransformations(data)
}

func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	if options == nil || options.FuzzGenerated.Component == nil || options.HttpClient == nil {
		return false, "", nil
	}

	gr := options.FuzzGenerated
	payload := a.ApplyInitialTransformation(gr.OriginalPayload, options.AnalyzerParameters)
	if payload == "" {
		return false, "", nil
	}

	if err := gr.Component.SetValue(gr.Key, payload); err != nil {
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
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", err
	}

	if strings.Contains(string(body), payload) {
		return true, "reflected payload detected (xss_context classifier WIP)", nil
	}

	return false, "", nil
}
