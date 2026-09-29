package xss

import (
	"io"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"golang.org/x/net/html"
)

const (
	analyzerName         = "xss_context"
	maxResponseBodyBytes = 10 * 1024 * 1024 // 10 MiB
)

// XSSAnalyzer implements the analyzers.Analyzer interface for XSS context detection.
type XSSAnalyzer struct{}

var _ analyzers.Analyzer = &XSSAnalyzer{}

func init() {
	analyzers.RegisterAnalyzer(analyzerName, &XSSAnalyzer{})
}

func (a *XSSAnalyzer) Name() string {
	return analyzerName
}

func (a *XSSAnalyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	return analyzers.ApplyPayloadTransformations(data)
}

func (a *XSSAnalyzer) Analyze(options *analyzers.Options) (bool, string, error) {
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
		_ = gr.Component.SetValue(gr.Key, gr.OriginalValue)
	}()

	rebuilt, err := gr.Component.Rebuild()
	if err != nil {
		return false, "", err
	}

	resp, err := options.HttpClient.Do(rebuilt)
	if err != nil {
		return false, "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return false, "", err
	}

	ctx, err := AnalyzeReflectionContext(string(body), payload)
	if err != nil {
		return false, "", err
	}
	if ctx == ContextUnknown {
		return false, "", nil
	}
	return true, "xss-reflected in " + ctx.String(), nil
}

// urlAttrs lists attributes whose values may contain navigable URIs.
// ping was missed initially, it fires a POST to the URL when <a> is clicked.
var urlAttrs = map[string]struct{}{
	"href":       {},
	"src":        {},
	"action":     {},
	"formaction": {},
	"data":       {},
	"poster":     {},
	"codebase":   {},
	"cite":       {},
	"background": {},
	"manifest":   {},
	"icon":       {},
	"ping":       {},
	"longdesc":   {},
}

// eventHandlers lists attributes that execute JavaScript when triggered.
var eventHandlers = map[string]struct{}{
	"onabort":              {},
	"onafterprint":         {},
	"onbeforeprint":        {},
	"onbeforeunload":       {},
	"onblur":               {},
	"oncancel":             {},
	"oncanplay":            {},
	"oncanplaythrough":     {},
	"onchange":             {},
	"onclick":              {},
	"onclose":              {},
	"oncontextmenu":        {},
	"oncopy":               {},
	"oncuechange":          {},
	"oncut":                {},
	"ondblclick":           {},
	"ondrag":               {},
	"ondragend":            {},
	"ondragenter":          {},
	"ondragleave":          {},
	"ondragover":           {},
	"ondragstart":          {},
	"ondrop":               {},
	"ondurationchange":     {},
	"onemptied":            {},
	"onended":              {},
	"onerror":              {},
	"onfocus":              {},
	"onfocusin":            {},
	"onfocusout":           {},
	"onhashchange":         {},
	"oninput":              {},
	"oninvalid":            {},
	"onkeydown":            {},
	"onkeypress":           {},
	"onkeyup":              {},
	"onload":               {},
	"onloadeddata":         {},
	"onloadedmetadata":     {},
	"onloadstart":          {},
	"onmessage":            {},
	"onmousedown":          {},
	"onmouseenter":         {},
	"onmouseleave":         {},
	"onmousemove":          {},
	"onmouseout":           {},
	"onmouseover":          {},
	"onmouseup":            {},
	"onoffline":            {},
	"ononline":             {},
	"onpagehide":           {},
	"onpageshow":           {},
	"onpaste":              {},
	"onpause":              {},
	"onplay":               {},
	"onplaying":            {},
	"onpopstate":           {},
	"onprogress":           {},
	"onratechange":         {},
	"onreset":              {},
	"onresize":             {},
	"onscroll":             {},
	"onsearch":             {},
	"onseeked":             {},
	"onseeking":            {},
	"onselect":             {},
	"onstalled":            {},
	"onstorage":            {},
	"onsubmit":             {},
	"onsuspend":            {},
	"ontimeupdate":         {},
	"ontoggle":             {},
	"onunload":             {},
	"onvolumechange":       {},
	"onwaiting":            {},
	"onwheel":              {},
	"onanimationstart":     {},
	"onanimationend":       {},
	"onanimationiteration": {},
	"ontransitionend":      {},
	"onpointerdown":        {},
	"onpointerup":          {},
	"onpointermove":        {},
	"onpointerover":        {},
	"onpointerout":         {},
	"onpointerenter":       {},
	"onpointerleave":       {},
	"onpointercancel":      {},
	"ongotpointercapture":  {},
	"onlostpointercapture": {},
	"ontouchstart":         {},
	"ontouchend":           {},
	"ontouchmove":          {},
	"ontouchcancel":        {},
	// added after review, these are newer DOM events that were missing
	"onauxclick":           {},
	"onbeforeinput":        {},
	"onformdata":           {},
	"onslotchange":         {},
	"onsecuritypolicyviolation": {},
}

// executableScriptTypes lists MIME types that browsers actually execute.
// Empty string covers <script> with no type attribute.
var executableScriptTypes = map[string]struct{}{
	"":                          {},
	"text/javascript":           {},
	"application/javascript":    {},
	"text/ecmascript":           {},
	"application/ecmascript":    {},
	"module":                    {},
	"text/jscript":              {},
	"text/livescript":           {},
	"text/x-ecmascript":        {},
	"text/x-javascript":        {},
	"application/x-javascript":  {},
	"application/x-ecmascript":  {},
}

// executableURLSinks maps URL attribute names to the set of tags where
// dangerous URIs (javascript:, vbscript:, data:text/html, etc.) actually
// execute or render a document. Other tag+attr combos stay as
// ContextHTMLAttributeURL — e.g. <img src="javascript:..."> doesn't execute.
var executableURLSinks = map[string]map[string]struct{}{
	"href":       {"a": {}, "area": {}},
	"src":        {"iframe": {}, "frame": {}, "embed": {}},
	"action":     {"form": {}},
	"formaction": {"button": {}, "input": {}},
	"data":       {"object": {}},
}

// AnalyzeReflectionContext determines the HTML context where the given marker
// is reflected in the response body. Uses golang.org/x/net/html tokenizer
// for parsing. Returns ContextUnknown if the marker is not found.
func AnalyzeReflectionContext(responseBody, marker string) (XSSContext, error) {
	if responseBody == "" || marker == "" {
		return ContextUnknown, nil
	}

	markerLower := strings.ToLower(marker)

	// bail early if the marker isn't anywhere in the body
	if !strings.Contains(strings.ToLower(responseBody), markerLower) {
		return ContextUnknown, nil
	}

	tokenizer := html.NewTokenizer(strings.NewReader(responseBody))

	var (
		inScript     bool
		inStyle      bool
		scriptIsExec bool
	)

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			// EOF is expected (end of doc), but surface real parse errors
			if err := tokenizer.Err(); err != nil && err != io.EOF {
				return ContextUnknown, err
			}
			return ContextUnknown, nil

		case html.CommentToken:
			if containsMarker(tokenizer.Token().Data, markerLower) {
				return ContextComment, nil
			}

		case html.StartTagToken, html.SelfClosingTagToken:
			tn, hasAttr := tokenizer.TagName()
			tagName := strings.ToLower(string(tn))

			// Important: TagAttr() is a forward-only iterator. If we checked
			// script type and marker in separate loops, the second loop would
			// see no attributes (already consumed). So we do both in one pass.
			if hasAttr {
				ctx, found, scriptType := scanAttributes(tokenizer, markerLower, tagName)
				if found {
					return ctx, nil
				}
				if tt == html.StartTagToken && tagName == "script" {
					inScript = true
					scriptIsExec = isScriptTypeExecutable(scriptType)
				}
			} else if tt == html.StartTagToken && tagName == "script" {
				inScript = true
				scriptIsExec = true // no attrs = executable
			}

			if tt == html.StartTagToken && tagName == "style" {
				inStyle = true
			}

		case html.EndTagToken:
			tn, _ := tokenizer.TagName()
			switch strings.ToLower(string(tn)) {
			case "script":
				inScript = false
			case "style":
				inStyle = false
			}

		case html.TextToken:
			if containsMarker(tokenizer.Token().Data, markerLower) {
				if inScript {
					if scriptIsExec {
						return ContextScript, nil
					}
					return ContextScriptData, nil
				}
				if inStyle {
					return ContextStyle, nil
				}
				return ContextHTMLBody, nil
			}
		}
	}
}

// scanAttributes walks all attributes in one pass. We need this because
// the tokenizer's TagAttr() is consumable, once you iterate through,
// the attributes are gone. Earlier version had a bug where checking the
// script type first would eat all the attrs before we could check for
// the marker, so <script src="MARKER"> would silently miss the reflection.
func scanAttributes(tokenizer *html.Tokenizer, markerLower, tagName string) (XSSContext, bool, string) {
	var markerCtx XSSContext
	markerFound := false
	scriptType := ""
	foundType := false

	for {
		key, val, more := tokenizer.TagAttr()
		attrName := strings.ToLower(string(key))
		attrValue := string(val)

		// HTML5 spec: browsers use the first type attribute when dupes exist.
		// Without this check, <script type="application/json" type="text/javascript">
		// would be classified as executable (last wins) when the browser treats it
		// as non-executable (first wins).
		if attrName == "type" && !foundType {
			scriptType = strings.ToLower(strings.TrimSpace(attrValue))
			foundType = true
		}

		if !markerFound {
			if containsMarker(attrValue, markerLower) {
				markerCtx = classifyAttributeContext(attrName, attrValue, tagName)
				markerFound = true
			} else if containsMarker(attrName, markerLower) {
				markerCtx = ContextHTMLAttribute
				markerFound = true
			}
		}

		if !more {
			break
		}
	}

	return markerCtx, markerFound, scriptType
}

// isScriptTypeExecutable returns true if the type value is something
// browsers will actually run (or empty, meaning no type was set).
// Strips MIME parameters first, browsers still execute
// "text/javascript; charset=utf-8" but the raw string wouldn't match
// the lookup table without this.
func isScriptTypeExecutable(scriptType string) bool {
	if i := strings.IndexByte(scriptType, ';'); i != -1 {
		scriptType = strings.TrimSpace(scriptType[:i])
	}
	_, isExec := executableScriptTypes[scriptType]
	return isExec
}

// classifyAttributeContext maps an attribute name to the right XSS context.
func classifyAttributeContext(attrName, attrValue, tagName string) XSSContext {
	if _, ok := eventHandlers[attrName]; ok {
		return ContextHTMLAttributeEvent
	}

	if attrName == "style" {
		return ContextStyle
	}

	if attrName == "srcdoc" {
		return ContextHTMLBody
	}

	if _, ok := urlAttrs[attrName]; ok {
		trimmed := strings.TrimSpace(strings.ToLower(attrValue))
		if strings.HasPrefix(trimmed, "javascript:") ||
			strings.HasPrefix(trimmed, "vbscript:") ||
			strings.HasPrefix(trimmed, "data:text/html") ||
			strings.HasPrefix(trimmed, "data:application/xhtml+xml") ||
			strings.HasPrefix(trimmed, "data:image/svg+xml") {
			// only promote to ContextScript if this tag+attr pair actually
			// executes dangerous URIs in browsers — <img src="javascript:...">
			// doesn't execute, <a href="javascript:..."> does
			if tags, ok := executableURLSinks[attrName]; ok {
				if _, ok := tags[tagName]; ok {
					return ContextScript
				}
			}
		}
		return ContextHTMLAttributeURL
	}

	return ContextHTMLAttribute
}

// containsMarker does a case-insensitive substring check.
// markerLower must already be lowercased by the caller.
func containsMarker(text, markerLower string) bool {
	return strings.Contains(strings.ToLower(text), markerLower)
}
