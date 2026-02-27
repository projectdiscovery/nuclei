package xss

import (
	"fmt"
	"strings"
	"testing"
)

const testCanary = "gtssCANARY12"

func TestDetermineContext(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		expected XSSContext
	}{
		// HTML text contexts
		{
			name:     "plain text",
			html:     fmt.Sprintf("<div>%s</div>", testCanary),
			expected: ContextHTMLText,
		},
		{
			name:     "text with siblings",
			html:     fmt.Sprintf("<p>Hello %s world</p>", testCanary),
			expected: ContextHTMLText,
		},

		// HTML comment
		{
			name:     "html comment",
			html:     fmt.Sprintf("<!-- %s -->", testCanary),
			expected: ContextHTMLComment,
		},

		// Attribute values
		{
			name:     "double-quoted attribute",
			html:     fmt.Sprintf(`<input value="%s">`, testCanary),
			expected: ContextAttrValueDoubleQuoted,
		},
		{
			name:     "single-quoted attribute",
			html:     fmt.Sprintf(`<input value='%s'>`, testCanary),
			expected: ContextAttrValueSingleQuoted,
		},
		{
			name:     "unquoted attribute",
			html:     fmt.Sprintf(`<input value=%s>`, testCanary),
			expected: ContextAttrValueUnquoted,
		},
		{
			name:     "attribute key repeated uses canary-bearing occurrence",
			html:     fmt.Sprintf(`<input value="safe"><input value='%s'>`, testCanary),
			expected: ContextAttrValueSingleQuoted,
		},
		{
			name:     "attribute key boundary match",
			html:     fmt.Sprintf(`<input data-value="safe" value=%s>`, testCanary),
			expected: ContextAttrValueUnquoted,
		},

		// Event handlers
		{
			name:     "onclick handler",
			html:     fmt.Sprintf(`<div onclick="%s">`, testCanary),
			expected: ContextEventHandler,
		},
		{
			name:     "onload handler",
			html:     fmt.Sprintf(`<img onload="%s">`, testCanary),
			expected: ContextEventHandler,
		},
		{
			name:     "onerror handler",
			html:     fmt.Sprintf(`<img onerror="%s">`, testCanary),
			expected: ContextEventHandler,
		},

		// URL attributes
		{
			name:     "href attribute",
			html:     fmt.Sprintf(`<a href="%s">link</a>`, testCanary),
			expected: ContextURLAttribute,
		},
		{
			name:     "src attribute",
			html:     fmt.Sprintf(`<img src="%s">`, testCanary),
			expected: ContextURLAttribute,
		},
		{
			name:     "action attribute",
			html:     fmt.Sprintf(`<form action="%s">`, testCanary),
			expected: ContextURLAttribute,
		},

		// Style attribute
		{
			name:     "style attribute",
			html:     fmt.Sprintf(`<div style="color: %s">`, testCanary),
			expected: ContextStyleAttribute,
		},

		// Script contexts
		{
			name:     "script double-quoted string",
			html:     fmt.Sprintf(`<script>var x = "%s";</script>`, testCanary),
			expected: ContextScriptStringDouble,
		},
		{
			name:     "script single-quoted string",
			html:     fmt.Sprintf(`<script>var x = '%s';</script>`, testCanary),
			expected: ContextScriptStringSingle,
		},
		{
			name:     "script template literal",
			html:     fmt.Sprintf("<script>var x = `%s`;</script>", testCanary),
			expected: ContextScriptTemplateLiteral,
		},
		{
			name:     "script expression",
			html:     fmt.Sprintf(`<script>var x = %s;</script>`, testCanary),
			expected: ContextScriptExpression,
		},
		{
			name:     "script line comment",
			html:     fmt.Sprintf("<script>// %s\n</script>", testCanary),
			expected: ContextScriptComment,
		},
		{
			name:     "script block comment",
			html:     fmt.Sprintf("<script>/* %s */</script>", testCanary),
			expected: ContextScriptBlockComment,
		},

		// CSS contexts
		{
			name:     "css value",
			html:     fmt.Sprintf("<style>.x { color: %s }</style>", testCanary),
			expected: ContextCSSValue,
		},
		{
			name:     "css url",
			html:     fmt.Sprintf("<style>div { background: url(%s) }</style>", testCanary),
			expected: ContextCSSURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			points := findReflections([]byte(tt.html), testCanary)
			if len(points) == 0 {
				t.Fatalf("no reflection points found for %q", tt.name)
			}
			got := points[0].Context
			if got != tt.expected {
				t.Errorf("got %s, want %s", got.String(), tt.expected.String())
			}
		})
	}
}

func TestNoReflection(t *testing.T) {
	html := `<div>Hello world</div>`
	points := findReflections([]byte(html), testCanary)
	if len(points) != 0 {
		t.Errorf("expected no reflections, got %d", len(points))
	}
}

func TestEncodedCanaryNotMatched(t *testing.T) {
	var (
		htmlEntity     strings.Builder
		percentEncoded strings.Builder
	)
	for i := 0; i < len(testCanary); i++ {
		ch := testCanary[i]
		fmt.Fprintf(&htmlEntity, "&#x%02x;", ch)
		fmt.Fprintf(&percentEncoded, "%%%02X", ch)
	}

	html := fmt.Sprintf(`<div>%s</div><script>var x="%s"</script>`, htmlEntity.String(), percentEncoded.String())
	points := findReflections([]byte(html), testCanary)
	if len(points) != 0 {
		t.Fatalf("expected no reflections for encoded canary, got %d", len(points))
	}
}

func TestMultipleReflections(t *testing.T) {
	html := fmt.Sprintf(`<div>%s</div><script>var x = "%s";</script>`, testCanary, testCanary)
	points := findReflections([]byte(html), testCanary)
	if len(points) < 2 {
		t.Fatalf("expected at least 2 reflections, got %d", len(points))
	}

	// Verify we get both HTML text and script string contexts
	contexts := make(map[XSSContext]bool)
	for _, p := range points {
		contexts[p.Context] = true
	}
	if !contexts[ContextHTMLText] {
		t.Error("expected ContextHTMLText in reflections")
	}
	if !contexts[ContextScriptStringDouble] {
		t.Error("expected ContextScriptStringDouble in reflections")
	}
}

func TestGenerateCanary(t *testing.T) {
	c1 := generateCanary()
	c2 := generateCanary()

	if c1 == c2 {
		t.Error("two canaries should not be identical")
	}
	if len(c1) != 12 { // "gtss" + 8 chars
		t.Errorf("canary length should be 12, got %d: %q", len(c1), c1)
	}
	if !strings.HasPrefix(c1, "gtss") {
		t.Errorf("canary should start with 'gtss', got %q", c1)
	}
}

// BenchmarkFindReflections measures context detection across all context types.
func BenchmarkFindReflections(b *testing.B) {
	bodies := map[string][]byte{
		"html_text":       []byte(fmt.Sprintf(`<html><body><div>%s</div></body></html>`, testCanary)),
		"attribute":       []byte(fmt.Sprintf(`<html><body><input value="%s"></body></html>`, testCanary)),
		"event_handler":   []byte(fmt.Sprintf(`<html><body><div onclick="%s"></div></body></html>`, testCanary)),
		"script_string":   []byte(fmt.Sprintf(`<html><head><script>var x = "%s";</script></head></html>`, testCanary)),
		"script_template": []byte(fmt.Sprintf("<html><head><script>var x = `%s`;</script></head></html>", testCanary)),
		"css_value":       []byte(fmt.Sprintf(`<html><head><style>.x { color: %s }</style></head></html>`, testCanary)),
		"css_url":         []byte(fmt.Sprintf(`<html><head><style>div { background: url(%s) }</style></head></html>`, testCanary)),
		"multi_reflect":   []byte(fmt.Sprintf(`<html><body><div>%s</div><script>var x = "%s";</script><style>.x{color:%s}</style></body></html>`, testCanary, testCanary, testCanary)),
	}

	for name, body := range bodies {
		b.Run(name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				findReflections(body, testCanary)
			}
		})
	}
}

// TestRealWorldReflections tests context detection on realistic HTML responses
// that mirror what you'd encounter during actual web application pentesting.
func TestRealWorldReflections(t *testing.T) {
	const canary = "gtssR3alW0rld"

	tests := []struct {
		name     string
		html     string
		expected []XSSContext // one per reflection, in order
	}{
		{
			name: "search results page — reflected query in heading and input",
			html: fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Search Results</title></head>
<body>
  <nav><a href="/">Home</a></nav>
  <h1>Results for "%s"</h1>
  <form action="/search" method="GET">
    <input type="text" name="q" value="%s">
    <button type="submit">Search</button>
  </form>
  <div class="results"><p>No results found.</p></div>
</body>
</html>`, canary, canary),
			expected: []XSSContext{ContextHTMLText, ContextAttrValueDoubleQuoted},
		},
		{
			name: "error page — reflected param in script variable and error message",
			html: fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <title>Error</title>
  <script>
    var errorCode = 404;
    var requestedPath = "%s";
    console.log("Not found: " + requestedPath);
  </script>
</head>
<body>
  <h1>404 Not Found</h1>
  <p>The page <code>%s</code> could not be found.</p>
</body>
</html>`, canary, canary),
			expected: []XSSContext{ContextScriptStringDouble, ContextHTMLText},
		},
		{
			name: "profile page — reflected username in multiple attribute types",
			html: fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Profile</title>
<style>
  .avatar { background-image: url(/avatars/%s.jpg); width: 100px; height: 100px; }
</style>
</head>
<body>
  <div class="avatar"></div>
  <a href="/user/%s">%s's Profile</a>
  <img src="/api/photo/%s" alt="Photo of %s" onerror="handleImgError('%s')">
</body>
</html>`, canary, canary, canary, canary, canary, canary),
			expected: []XSSContext{
				ContextCSSURL,                // url(/avatars/CANARY.jpg)
				ContextURLAttribute,          // href="/user/CANARY"
				ContextHTMLText,              // CANARY's Profile
				ContextURLAttribute,          // src="/api/photo/CANARY"
				ContextAttrValueDoubleQuoted, // alt="Photo of CANARY"
				ContextEventHandler,          // onerror="handleImgError('CANARY')"
			},
		},
		{
			name: "SPA boot page — reflected config in JSON init script",
			html: fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>App</title>
  <script>
    window.__CONFIG__ = {
      apiBase: "/api/v1",
      userName: "%s",
      locale: "en-US"
    };
  </script>
</head>
<body>
  <div id="app"></div>
  <script src="/static/bundle.js"></script>
</body>
</html>`, canary),
			expected: []XSSContext{ContextScriptStringDouble},
		},
		{
			name: "comment form — reflected input in textarea and hidden field",
			html: fmt.Sprintf(`<!DOCTYPE html>
<html><body>
  <form method="POST" action="/comment">
    <input type="hidden" name="redirect" value="%s">
    <textarea name="body">%s</textarea>
    <button>Submit</button>
  </form>
</body></html>`, canary, canary),
			expected: []XSSContext{ContextAttrValueDoubleQuoted, ContextHTMLText},
		},
		{
			name: "inline event handler with template literal in script",
			html: fmt.Sprintf(`<!DOCTYPE html>
<html><body>
  <div id="output"></div>
  <script>
    const name = `+"`%s`"+`;
    document.getElementById('output').innerHTML = name;
  </script>
  <button onclick="alert('%s')">Click</button>
</body></html>`, canary, canary),
			expected: []XSSContext{ContextScriptTemplateLiteral, ContextEventHandler},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			points := findReflections([]byte(tt.html), canary)
			if len(points) != len(tt.expected) {
				t.Fatalf("expected %d reflections, got %d", len(tt.expected), len(points))
			}
			for i, pt := range points {
				if pt.Context != tt.expected[i] {
					t.Errorf("reflection[%d]: got %s, want %s", i, pt.Context.String(), tt.expected[i].String())
				}
			}
		})
	}
}

func TestContextStrings(t *testing.T) {
	tests := []struct {
		ctx      XSSContext
		expected string
	}{
		{ContextHTMLText, "xss_context:html_text"},
		{ContextHTMLComment, "xss_context:html_comment"},
		{ContextAttrValueDoubleQuoted, "xss_context:attr_value_double_quoted"},
		{ContextEventHandler, "xss_context:event_handler"},
		{ContextURLAttribute, "xss_context:url_attribute"},
		{ContextScriptStringDouble, "xss_context:script_string_double"},
		{ContextScriptTemplateLiteral, "xss_context:script_template_literal"},
		{ContextCSSURL, "xss_context:css_url"},
		{ContextUnknown, "xss_context:unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.ctx.String(); got != tt.expected {
				t.Errorf("got %q, want %q", got, tt.expected)
			}
		})
	}
}
