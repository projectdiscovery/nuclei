package xss

import (
	"io"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

const (
	analyzerName         = "xss_context"
	maxResponseBodyBytes = 10 * 1024 * 1024 // 10 MiB
	contextScript        = "script"
	contextAttribute     = "attribute"
	contextComment       = "comment"
	contextHTML          = "html"
	contextRawHTML       = "raw_html"
)

// Analyzer is an XSS reflection analyzer that classifies where payloads are reflected.
type Analyzer struct{}

var _ analyzers.Analyzer = &Analyzer{}

func init() {
	analyzers.RegisterAnalyzer(analyzerName, &Analyzer{})
}

// Name returns the analyzer identifier used in templates.
func (a *Analyzer) Name() string {
	return analyzerName
}

// ApplyInitialTransformation applies standard fuzz payload transformations to the payload.
func (a *Analyzer) ApplyInitialTransformation(data string, _ map[string]interface{}) string {
	return analyzers.ApplyPayloadTransformations(data)
}

// Analyze replays the generated request and inspects reflection context for the injected payload.
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	if options == nil || options.FuzzGenerated.Component == nil || options.HttpClient == nil {
		return false, "", nil
	}

	gr := options.FuzzGenerated
	payload := gr.Value
	if payload == "" {
		return false, "", nil
	}

	if err := gr.Component.SetValue(gr.Key, payload); err != nil {
		return false, "", err
	}
	defer func() {
		_ = gr.Component.SetValue(gr.Key, gr.Value)
	}()

	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return false, "", err
	}

	resp, err := options.HttpClient.Do(rebuilt)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes+1))
	if err != nil {
		return false, "", err
	}
	if len(body) > maxResponseBodyBytes {
		body = body[:maxResponseBodyBytes]
	}

	matched, reason := classifyContexts(string(body), payload)
	if !matched {
		return false, "", nil
	}
	return true, reason, nil
}

func classifyContexts(body, payload string) (bool, string) {
	if body == "" || payload == "" || !strings.Contains(body, payload) {
		return false, ""
	}

	context := contextRawHTML
	tokenizer := html.NewTokenizer(strings.NewReader(body))
	inScript := false

	for {
		switch tokenizer.Next() {
		case html.ErrorToken:
			return true, buildReason(context)
		case html.StartTagToken:
			token := tokenizer.Token()
			if token.DataAtom == atom.Script {
				inScript = true
			}
			context = higherPriorityContext(context, contextFromTag(token, payload))
		case html.SelfClosingTagToken:
			token := tokenizer.Token()
			context = higherPriorityContext(context, contextFromTag(token, payload))
		case html.EndTagToken:
			token := tokenizer.Token()
			if token.DataAtom == atom.Script {
				inScript = false
			}
		case html.CommentToken:
			if strings.Contains(tokenizer.Token().Data, payload) {
				context = higherPriorityContext(context, contextComment)
			}
		case html.TextToken:
			text := tokenizer.Token().Data
			if !strings.Contains(text, payload) {
				continue
			}
			if inScript {
				context = higherPriorityContext(context, contextScript)
			} else {
				context = higherPriorityContext(context, contextHTML)
			}
		}

		if context == contextScript {
			return true, buildReason(context)
		}
	}
}

func contextFromTag(token html.Token, payload string) string {
	for _, attr := range token.Attr {
		if strings.Contains(attr.Key, payload) || strings.Contains(attr.Val, payload) {
			return contextAttribute
		}
	}
	if strings.Contains(token.Data, payload) {
		return contextRawHTML
	}
	return ""
}

func higherPriorityContext(current, candidate string) string {
	if candidate == "" {
		return current
	}

	if contextPriority(candidate) > contextPriority(current) {
		return candidate
	}
	return current
}

func contextPriority(context string) int {
	switch context {
	case contextScript:
		return 5
	case contextAttribute:
		return 4
	case contextHTML:
		return 3
	case contextComment:
		return 2
	case contextRawHTML:
		return 1
	default:
		return 0
	}
}

func buildReason(context string) string {
	return "reflected payload detected in " + context + " context"
}
