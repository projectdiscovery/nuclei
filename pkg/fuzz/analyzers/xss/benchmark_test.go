package xss

import (
	"fmt"
	"strings"
	"testing"
)

// BenchmarkDetectContext_NoReflection measures fast-path when marker is absent.
func BenchmarkDetectContext_NoReflection(b *testing.B) {
	body := `<html><body><h1>Hello World</h1><p>Some text</p></body></html>`
	marker := "NUCLEI_NOTFOUND"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DetectReflections(body, marker)
	}
}

// BenchmarkDetectContext_HTMLContext measures detection in simple HTML text.
func BenchmarkDetectContext_HTMLContext(b *testing.B) {
	body := `<html><body><div>NUCLEI_XSS_MARKER</div></body></html>`
	marker := "NUCLEI_XSS_MARKER"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DetectReflections(body, marker)
	}
}

// BenchmarkDetectContext_ScriptContext measures detection inside a script block.
func BenchmarkDetectContext_ScriptContext(b *testing.B) {
	body := `<html><script>var user = "NUCLEI_XSS_MARKER";</script></html>`
	marker := "NUCLEI_XSS_MARKER"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DetectReflections(body, marker)
	}
}

// BenchmarkDetectContext_AttributeContext measures detection in attribute values.
func BenchmarkDetectContext_AttributeContext(b *testing.B) {
	body := `<html><body><input type="text" value="NUCLEI_XSS_MARKER"></body></html>`
	marker := "NUCLEI_XSS_MARKER"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DetectReflections(body, marker)
	}
}

// BenchmarkDetectContext_EventHandler measures detection in event handler attributes.
func BenchmarkDetectContext_EventHandler(b *testing.B) {
	body := `<html><body><div onclick="NUCLEI_XSS_MARKER">click</div></body></html>`
	marker := "NUCLEI_XSS_MARKER"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DetectReflections(body, marker)
	}
}

// BenchmarkDetectContext_LargePage measures detection on a realistic page size.
func BenchmarkDetectContext_LargePage(b *testing.B) {
	var sb strings.Builder
	sb.WriteString("<html><body>")
	for i := 0; i < 200; i++ {
		sb.WriteString(fmt.Sprintf(`<div class="item-%d"><p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p></div>`, i))
	}
	sb.WriteString(`<input type="text" value="NUCLEI_XSS_MARKER">`)
	sb.WriteString("</body></html>")
	body := sb.String()
	marker := "NUCLEI_XSS_MARKER"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DetectReflections(body, marker)
	}
}

// BenchmarkDetectContext_MultipleReflections measures detection with many reflections.
func BenchmarkDetectContext_MultipleReflections(b *testing.B) {
	body := `<html><body>` +
		`<div>NUCLEI_XSS_MARKER</div>` +
		`<input value="NUCLEI_XSS_MARKER">` +
		`<script>var x = "NUCLEI_XSS_MARKER";</script>` +
		`<!-- NUCLEI_XSS_MARKER -->` +
		`</body></html>`
	marker := "NUCLEI_XSS_MARKER"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DetectReflections(body, marker)
	}
}

// BenchmarkIsEventHandler measures event handler lookup performance.
func BenchmarkIsEventHandler(b *testing.B) {
	names := []string{"onclick", "OnMouseOver", "href", "class", "ONERROR", "data-custom"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, n := range names {
			isEventHandler(n)
		}
	}
}

// BenchmarkSelectPayloads measures payload selection and filtering.
func BenchmarkSelectPayloads(b *testing.B) {
	ref := ReflectionInfo{
		Context:        ContextHTMLText,
		AvailableChars: CharacterSet{LessThan: true, GreaterThan: true, DoubleQuote: true, SingleQuote: true, Slash: true, Backtick: true, Parenthesis: true, Equals: true},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SelectPayloads(ref, nil)
	}
}
