package xss

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
)

type Analyzer struct{}

var _ analyzers.Analyzer = &Analyzer{}

func init() {
	analyzers.RegisterAnalyzer(AnalyzerName, &Analyzer{})
}

func (a *Analyzer) Name() string {
	return AnalyzerName
}

func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	canary := DefaultCanary
	if params != nil {
		if v, ok := params["canary"].(string); ok && v != "" {
			canary = v
		}
	}
	data = strings.ReplaceAll(data, "[XSS_CANARY]", canary)
	return analyzers.ApplyPayloadTransformations(data)
}

func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	if options == nil || options.ResponseBody == "" {
		return false, "", nil
	}

	marker := options.FuzzGenerated.Value
	if marker == "" {
		marker = options.FuzzGenerated.OriginalPayload
	}
	if marker == "" {
		return false, "", nil
	}

	reflections := DetectReflections(options.ResponseBody, marker)
	if len(reflections) == 0 {
		gologger.Verbose().Msgf("[%s] No reflections found for marker", a.Name())
		return false, "", nil
	}

	gologger.Verbose().Msgf("[%s] Found %d reflection(s)", a.Name(), len(reflections))

	sort.SliceStable(reflections, func(i, j int) bool {
		return reflections[i].PriorityWeight < reflections[j].PriorityWeight
	})

	for _, ref := range reflections {
		if ref.Context == ContextUnknown {
			continue
		}

		payloads := SelectPayloads(ref, options.AnalyzerParameters)
		if len(payloads) == 0 {
			gologger.Verbose().Msgf("[%s] No usable payloads for context %s (chars filtered)", a.Name(), ref.Context)
			continue
		}

		gologger.Verbose().Msgf("[%s] context=%s, trying %d payload(s)", a.Name(), ref.Context, len(payloads))

		for _, payload := range payloads {
			ok, err := replayAndVerify(options, payload, ref.Context)
			if err != nil {
				continue
			}
			if ok {
				details := fmt.Sprintf(
					"[xss_context] XSS confirmed: parameter=%s context=%s payload=%q chars=<:%v >:%v ':%v \":%v /:%v `:%v",
					options.FuzzGenerated.Parameter,
					ref.Context.String(),
					payload,
					ref.AvailableChars.LessThan,
					ref.AvailableChars.GreaterThan,
					ref.AvailableChars.SingleQuote,
					ref.AvailableChars.DoubleQuote,
					ref.AvailableChars.Slash,
					ref.AvailableChars.Backtick,
				)
				gologger.Verbose().Msgf("[%s] %s", a.Name(), details)
				return true, details, nil
			}
		}
	}

	gologger.Verbose().Msgf("[%s] No exploitable XSS after verification", a.Name())
	return false, "", nil
}

func replayAndVerify(options *analyzers.Options, payload string, expected ContextType) (bool, error) {
	gr := options.FuzzGenerated
	if gr.Component == nil || options.HttpClient == nil {
		return false, fmt.Errorf("missing replay dependencies")
	}

	original := gr.Value
	if original == "" {
		original = gr.OriginalValue
	}

	if err := gr.Component.SetValue(gr.Key, payload); err != nil {
		return false, err
	}
	defer func() {
		if original != "" {
			_ = gr.Component.SetValue(gr.Key, original)
		}
	}()

	req, err := gr.Component.Rebuild()
	if err != nil {
		return false, err
	}

	resp, err := options.HttpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return false, err
	}

	return verifyReplayBody(string(body), payload, expected), nil
}

func verifyReplayBody(body, payload string, expected ContextType) bool {
	switch expected {
	case ContextScriptBlock, ContextScriptStringDouble, ContextScriptStringSingle, ContextScriptTemplate:
		return strings.Contains(body, "alert(1)")
	case ContextAttributeDoubleQuoted, ContextAttributeSingleQuoted, ContextAttributeUnquoted:
		return strings.Contains(body, "onfocus=alert(1)") ||
			strings.Contains(body, "onmouseover=alert(1)") ||
			strings.Contains(body, "onerror=alert(1)")
	case ContextHTMLText, ContextRCDATA, ContextStyle:
		return (strings.Contains(body, "<svg") || strings.Contains(body, "<img") ||
			strings.Contains(body, "<script")) && strings.Contains(body, "alert(1)")
	case ContextComment:
		return (strings.Contains(body, "<img") || strings.Contains(body, "<svg")) &&
			strings.Contains(body, "alert(1)")
	case ContextURLAttribute:
		return strings.Contains(body, "javascript:alert")
	default:
		return strings.Contains(body, payload)
	}
}
