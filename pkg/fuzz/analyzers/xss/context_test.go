package xss

import (
	"testing"
)

// ─── DetectReflections ────────────────────────────────────────────────────────

func TestDetectReflections_HTMLText(t *testing.T) {
	body := `<html><body><p>Hello nucleiXYZ world</p></body></html>`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection")
	}
	got := refs[0].Context
	if got != ContextHTMLText {
		t.Errorf("expected ContextHTMLText, got %s", got)
	}
}

func TestDetectReflections_AttributeDoubleQuoted(t *testing.T) {
	body := `<input value="nucleiXYZ">`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection")
	}
	got := refs[0].Context
	if got != ContextAttribute {
		t.Errorf("expected ContextAttribute, got %s", got)
	}
	if refs[0].QuoteChar != '"' {
		t.Errorf("expected double-quote, got %q", refs[0].QuoteChar)
	}
}

func TestDetectReflections_AttributeSingleQuoted(t *testing.T) {
	body := `<input value='nucleiXYZ'>`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection")
	}
	if refs[0].Context != ContextAttribute {
		t.Errorf("expected ContextAttribute, got %s", refs[0].Context)
	}
	if refs[0].QuoteChar != '\'' {
		t.Errorf("expected single-quote, got %q", refs[0].QuoteChar)
	}
}

func TestDetectReflections_AttributeUnquoted(t *testing.T) {
	body := `<input value=nucleiXYZ>`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection")
	}
	if refs[0].Context != ContextAttributeUnquoted {
		t.Errorf("expected ContextAttributeUnquoted, got %s", refs[0].Context)
	}
}

func TestDetectReflections_EventHandler(t *testing.T) {
	body := `<img src=x onerror="nucleiXYZ">`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection")
	}
	best := BestReflection(refs)
	if best.Context != ContextScript {
		t.Errorf("expected ContextScript for event handler, got %s", best.Context)
	}
}

func TestDetectReflections_ScriptBlock(t *testing.T) {
	body := `<script>var x = nucleiXYZ;</script>`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection")
	}
	if refs[0].Context != ContextScript {
		t.Errorf("expected ContextScript, got %s", refs[0].Context)
	}
}

func TestDetectReflections_ScriptStringLiteral(t *testing.T) {
	body := `<script>var x = "nucleiXYZ";</script>`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection")
	}
	if refs[0].Context != ContextScriptString {
		t.Errorf("expected ContextScriptString, got %s", refs[0].Context)
	}
}

func TestDetectReflections_StyleBlock(t *testing.T) {
	body := `<style>.nucleiXYZ { color: red; }</style>`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection")
	}
	if refs[0].Context != ContextStyle {
		t.Errorf("expected ContextStyle, got %s", refs[0].Context)
	}
}

func TestDetectReflections_HTMLComment(t *testing.T) {
	body := `<!-- nucleiXYZ -->`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection")
	}
	if refs[0].Context != ContextHTMLComment {
		t.Errorf("expected ContextHTMLComment, got %s", refs[0].Context)
	}
}

func TestDetectReflections_NoReflection(t *testing.T) {
	body := `<html><body><p>Nothing here</p></body></html>`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) != 0 {
		t.Errorf("expected no reflections, got %d", len(refs))
	}
}

// ─── Bug Fix #1: javascript: URI in URL attributes ────────────────────────────

func TestDetectReflections_JavascriptHref(t *testing.T) {
	// javascript: URI in href MUST be ContextScript, not ContextAttribute
	body := `<a href="javascript:nucleiXYZ()">click</a>`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection")
	}
	best := BestReflection(refs)
	if best.Context != ContextScript {
		t.Errorf("BUG #1: javascript: href should be ContextScript, got %s", best.Context)
	}
}

func TestDetectReflections_JavascriptSrc(t *testing.T) {
	body := `<iframe src="javascript:nucleiXYZ"></iframe>`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection")
	}
	best := BestReflection(refs)
	if best.Context != ContextScript {
		t.Errorf("BUG #1: javascript: src should be ContextScript, got %s", best.Context)
	}
}

func TestDetectReflections_JavascriptAction(t *testing.T) {
	body := `<form action="javascript:nucleiXYZ()"><input type=submit></form>`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection")
	}
	best := BestReflection(refs)
	if best.Context != ContextScript {
		t.Errorf("BUG #1: javascript: action should be ContextScript, got %s", best.Context)
	}
}

func TestDetectReflections_JavascriptFormaction(t *testing.T) {
	body := `<button formaction="javascript:nucleiXYZ()">go</button>`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection")
	}
	best := BestReflection(refs)
	if best.Context != ContextScript {
		t.Errorf("BUG #1: javascript: formaction should be ContextScript, got %s", best.Context)
	}
}

func TestDetectReflections_JavascriptURI_CaseInsensitive(t *testing.T) {
	// Browsers accept JAVASCRIPT:, JavaScript:, jAvAsCrIpT:
	body := `<a href="JAVASCRIPT:nucleiXYZ()">click</a>`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection")
	}
	best := BestReflection(refs)
	if best.Context != ContextScript {
		t.Errorf("BUG #1: JAVASCRIPT: (uppercase) href should be ContextScript, got %s", best.Context)
	}
}

func TestDetectReflections_JavascriptURI_WithLeadingWhitespace(t *testing.T) {
	// Browsers strip leading whitespace/control chars before checking the scheme
	body := "<a href=\"  javascript:nucleiXYZ()\">click</a>"
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection")
	}
	best := BestReflection(refs)
	if best.Context != ContextScript {
		t.Errorf("BUG #1: javascript: with leading spaces should be ContextScript, got %s", best.Context)
	}
}

func TestDetectReflections_NonJavascriptHref_IsAttribute(t *testing.T) {
	// A plain https: href should remain ContextAttribute
	body := `<a href="https://example.com/nucleiXYZ">click</a>`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection")
	}
	best := BestReflection(refs)
	if best.Context == ContextScript {
		t.Errorf("https: href should NOT be ContextScript, got %s", best.Context)
	}
}

// ─── Bug Fix #2: <script type="application/json"> not executable ──────────────

func TestDetectReflections_JsonScriptBlock_NotScript(t *testing.T) {
	// Marker inside application/json script block MUST NOT be ContextScript
	body := `<script type="application/json">{"key":"nucleiXYZ"}</script>`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection (as HTML text)")
	}
	for _, r := range refs {
		if r.Context == ContextScript || r.Context == ContextScriptString {
			t.Errorf("BUG #2: application/json block should NOT be ContextScript/ContextScriptString, got %s", r.Context)
		}
	}
}

func TestDetectReflections_JsonLdScriptBlock_NotScript(t *testing.T) {
	body := `<script type="application/ld+json">{"@context":"http://schema.org","name":"nucleiXYZ"}</script>`
	refs := DetectReflections(body, "nucleiXYZ")
	for _, r := range refs {
		if r.Context == ContextScript || r.Context == ContextScriptString {
			t.Errorf("BUG #2: application/ld+json block should NOT be ContextScript, got %s", r.Context)
		}
	}
}

func TestDetectReflections_TemplateScriptBlock_NotScript(t *testing.T) {
	body := `<script type="text/template">Hello nucleiXYZ</script>`
	refs := DetectReflections(body, "nucleiXYZ")
	for _, r := range refs {
		if r.Context == ContextScript || r.Context == ContextScriptString {
			t.Errorf("BUG #2: text/template block should NOT be ContextScript, got %s", r.Context)
		}
	}
}

func TestDetectReflections_JavascriptScriptBlock_IsScript(t *testing.T) {
	// Explicit text/javascript should still be executable
	body := `<script type="text/javascript">var x = nucleiXYZ;</script>`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection")
	}
	best := BestReflection(refs)
	if best.Context != ContextScript {
		t.Errorf("text/javascript block should be ContextScript, got %s", best.Context)
	}
}

func TestDetectReflections_ModuleScriptBlock_IsScript(t *testing.T) {
	body := `<script type="module">import {nucleiXYZ} from './x.js';</script>`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection")
	}
	best := BestReflection(refs)
	if best.Context != ContextScript && best.Context != ContextScriptString {
		t.Errorf("module script block should be ContextScript*, got %s", best.Context)
	}
}

func TestDetectReflections_ScriptBlockNoType_IsScript(t *testing.T) {
	// <script> with no type attribute defaults to text/javascript
	body := `<script>nucleiXYZ</script>`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection")
	}
	best := BestReflection(refs)
	if best.Context != ContextScript {
		t.Errorf("script with no type should be ContextScript, got %s", best.Context)
	}
}

// ─── Bug Fix #3: Case-insensitive initial marker check ───────────────────────

func TestDetectReflections_CaseInsensitiveMarker(t *testing.T) {
	// Server uppercases the canary — must still detect the reflection
	body := `<p>NUCLEIXYZ is here</p>`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Errorf("BUG #3: case-insensitive marker check failed — no reflections found when server uppercased canary")
	}
}

func TestDetectReflections_MixedCaseMarker(t *testing.T) {
	body := `<input value="NuClEiXyZ">`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Errorf("BUG #3: mixed-case marker not detected — early exit guard was case-sensitive")
	}
}

// ─── Bug Fix #4: srcdoc attribute context ────────────────────────────────────

func TestDetectReflections_SrcdocAttribute(t *testing.T) {
	// srcdoc="<p>nucleiXYZ</p>" is full HTML injection, must be ContextHTMLText
	body := `<iframe srcdoc="<p>nucleiXYZ</p>"></iframe>`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) == 0 {
		t.Fatal("expected at least one reflection for srcdoc")
	}
	found := false
	for _, r := range refs {
		if r.AttrName == "srcdoc" {
			found = true
			if r.Context != ContextHTMLText {
				t.Errorf("BUG #4: srcdoc should be ContextHTMLText, got %s", r.Context)
			}
		}
	}
	if !found {
		t.Error("no reflection found for srcdoc attribute specifically")
	}
}

// ─── isExecutableScriptTag ────────────────────────────────────────────────────

func TestIsExecutableScriptTag(t *testing.T) {
	tests := []struct {
		rawToken   string
		executable bool
	}{
		{`<script>`, true},
		{`<script type="text/javascript">`, true},
		{`<script type='text/javascript'>`, true},
		{`<script type="application/javascript">`, true},
		{`<script type="module">`, true},
		{`<script type="application/json">`, false},
		{`<script type='application/json'>`, false},
		{`<script type="application/ld+json">`, false},
		{`<script type="text/template">`, false},
		{`<script type="text/x-template">`, false},
		{`<script type="text/html">`, false},
		{`<script type="text/plain">`, false},
		{`<script type=application/json>`, false},
	}
	for _, tt := range tests {
		got := isExecutableScriptTag(tt.rawToken)
		if got != tt.executable {
			t.Errorf("isExecutableScriptTag(%q) = %v, want %v", tt.rawToken, got, tt.executable)
		}
	}
}

// ─── hasJavaScriptScheme ─────────────────────────────────────────────────────

func TestHasJavaScriptScheme(t *testing.T) {
	tests := []struct {
		val  string
		want bool
	}{
		{"javascript:alert(1)", true},
		{"JAVASCRIPT:alert(1)", true},
		{"JavaScript:alert(1)", true},
		{"  javascript:alert(1)", true},
		{"\tjavascript:alert(1)", true},
		{"https://example.com", false},
		{"http://evil.com", false},
		{"/path/to/page", false},
		{"data:text/html,<h1>hi</h1>", false},
		{"vbscript:msgbox(1)", false},
	}
	for _, tt := range tests {
		got := hasJavaScriptScheme(tt.val)
		if got != tt.want {
			t.Errorf("hasJavaScriptScheme(%q) = %v, want %v", tt.val, got, tt.want)
		}
	}
}

// ─── isURLAttribute ──────────────────────────────────────────────────────────

func TestIsURLAttribute(t *testing.T) {
	yes := []string{"href", "src", "action", "formaction", "data", "poster", "ping"}
	no := []string{"class", "id", "onclick", "value", "name", "style"}

	for _, a := range yes {
		if !isURLAttribute(a) {
			t.Errorf("isURLAttribute(%q) should be true", a)
		}
	}
	for _, a := range no {
		if isURLAttribute(a) {
			t.Errorf("isURLAttribute(%q) should be false", a)
		}
	}
}

// ─── BestReflection priority ─────────────────────────────────────────────────

func TestBestReflection_PrioritisesScript(t *testing.T) {
	refs := []ReflectionInfo{
		{Context: ContextHTMLText},
		{Context: ContextScript},
		{Context: ContextAttribute},
	}
	best := BestReflection(refs)
	if best == nil || best.Context != ContextScript {
		t.Errorf("BestReflection should pick ContextScript (priority 5), got %v", best)
	}
}

func TestBestReflection_Empty(t *testing.T) {
	if BestReflection(nil) != nil {
		t.Error("BestReflection(nil) should return nil")
	}
}

func TestBestReflection_Single(t *testing.T) {
	refs := []ReflectionInfo{{Context: ContextHTMLComment}}
	best := BestReflection(refs)
	if best.Context != ContextHTMLComment {
		t.Errorf("expected ContextHTMLComment, got %s", best.Context)
	}
}

// ─── detectScriptStringContext ───────────────────────────────────────────────

func TestDetectScriptStringContext_BareCode(t *testing.T) {
	ctx := detectScriptStringContext(`var x = nucleiXYZ;`, "nucleiXYZ")
	if ctx != ContextScript {
		t.Errorf("bare JS code: expected ContextScript, got %s", ctx)
	}
}

func TestDetectScriptStringContext_DoubleQuotedString(t *testing.T) {
	ctx := detectScriptStringContext(`var x = "nucleiXYZ";`, "nucleiXYZ")
	if ctx != ContextScriptString {
		t.Errorf("double-quoted: expected ContextScriptString, got %s", ctx)
	}
}

func TestDetectScriptStringContext_SingleQuotedString(t *testing.T) {
	ctx := detectScriptStringContext(`var x = 'nucleiXYZ';`, "nucleiXYZ")
	if ctx != ContextScriptString {
		t.Errorf("single-quoted: expected ContextScriptString, got %s", ctx)
	}
}

func TestDetectScriptStringContext_BacktickTemplate(t *testing.T) {
	ctx := detectScriptStringContext("var x = `nucleiXYZ`;", "nucleiXYZ")
	if ctx != ContextScriptString {
		t.Errorf("backtick template: expected ContextScriptString, got %s", ctx)
	}
}

func TestDetectScriptStringContext_EscapedQuote(t *testing.T) {
	// The \' before the marker should NOT close the string
	ctx := detectScriptStringContext(`var x = 'it\'s nucleiXYZ';`, "nucleiXYZ")
	if ctx != ContextScriptString {
		t.Errorf("escaped quote: expected ContextScriptString, got %s", ctx)
	}
}

// ─── Character survival: independent checks ─────────────────────────────────

func TestDetectCharacterSurvival_IndependentChecks(t *testing.T) {
	canary := "nucleiTEST1234"

	// Only > survives (< is encoded), checks must be independent
	body := canary + "&lt;" + canary + ">"
	chars := detectCharacterSurvival(body, canary)
	if !chars.GreaterThan {
		t.Error("GreaterThan should be true when > survives independently")
	}
	// < is encoded as &lt; so raw < is not present after canary
	if chars.LessThan {
		t.Error("LessThan should be false when < is encoded")
	}
}

func TestDetectCharacterSurvival_AllSurvive(t *testing.T) {
	canary := "nucleiABCD5678"
	body := canary + `<>"'/`
	chars := detectCharacterSurvival(body, canary)
	if !chars.LessThan || !chars.GreaterThan || !chars.DoubleQuote || !chars.SingleQuote || !chars.ForwardSlash {
		t.Errorf("all chars should survive, got %+v", chars)
	}
}

func TestDetectCharacterSurvival_NoneSurvive(t *testing.T) {
	canary := "nucleiNONE0000"
	body := canary + "encoded"
	chars := detectCharacterSurvival(body, canary)
	if chars.LessThan || chars.GreaterThan || chars.DoubleQuote || chars.SingleQuote || chars.ForwardSlash {
		t.Errorf("no chars should survive, got %+v", chars)
	}
}

func TestDetectCharacterSurvival_OnlyQuotesSurvive(t *testing.T) {
	canary := "nucleiQUOT1234"
	// Only quotes survive, angle brackets encoded
	body := canary + `"` + canary + "'"
	chars := detectCharacterSurvival(body, canary)
	if chars.LessThan || chars.GreaterThan {
		t.Error("angle brackets should not survive")
	}
	if !chars.DoubleQuote || !chars.SingleQuote {
		t.Error("quotes should survive independently")
	}
}

// ─── extractCanaryFromValue ──────────────────────────────────────────────────

func TestExtractCanaryFromValue(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{"nucleiABCDEFGH<>\"'/", "nucleiABCDEFGH"},
		{"prefix nuclei12345678 suffix", "nuclei12345678"},
		{"no canary here", ""},
		{"nuclei", ""}, // too short
		{"nucleiABC", ""}, // only 3 chars after prefix
	}
	for _, tt := range tests {
		got := extractCanaryFromValue(tt.value)
		if got != tt.want {
			t.Errorf("extractCanaryFromValue(%q) = %q, want %q", tt.value, got, tt.want)
		}
	}
}

// ─── Combined scenario: multiple reflections ─────────────────────────────────

func TestDetectReflections_MultipleContexts(t *testing.T) {
	// Marker appears in both an attribute and a script block
	body := `<html>
<script>var data = "nucleiXYZ";</script>
<input value="nucleiXYZ">
</html>`
	refs := DetectReflections(body, "nucleiXYZ")
	if len(refs) < 2 {
		t.Fatalf("expected at least 2 reflections, got %d", len(refs))
	}
	best := BestReflection(refs)
	// Script context (5) beats attribute context (3)
	if best.Context != ContextScriptString {
		t.Errorf("with script+attribute, BestReflection should pick script context, got %s", best.Context)
	}
}
