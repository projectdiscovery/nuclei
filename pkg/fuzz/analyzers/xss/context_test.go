package xss

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContextAnalyzer_JavascriptURI(t *testing.T) {
	analyzer := NewContextAnalyzer()
	
	// Test javascript: URI detection (Issue #7086)
	response := `<a href="javascript:alert('XSS')">click</a>`
	canary := "nucleiXSScanary"
	
	ctx, err := analyzer.AnalyzeContext(response, canary)
	require.NoError(t, err)
	require.Equal(t, ContextJavascriptURI, ctx)
}

func TestContextAnalyzer_JavascriptURICaseInsensitive(t *testing.T) {
	analyzer := NewContextAnalyzer()
	
	// Test case-insensitive javascript: URI detection (Issue #7086)
	response := `<a href="JavaScript:alert('XSS')">click</a>`
	canary := "nucleiXSScanary"
	
	ctx, err := analyzer.AnalyzeContext(response, canary)
	require.NoError(t, err)
	require.Equal(t, ContextJavascriptURI, ctx)
}

func TestContextAnalyzer_JSONScript(t *testing.T) {
	analyzer := NewContextAnalyzer()
	
	// Test JSON script block detection (Issue #7086)
	response := `<script type="application/json">{"key": "value"}</script>`
	canary := "nucleiXSScanary"
	
	ctx, err := analyzer.AnalyzeContext(response, canary)
	require.NoError(t, err)
	require.Equal(t, ContextJSON, ctx)
}

func TestContextAnalyzer_JSONLDScript(t *testing.T) {
	analyzer := NewContextAnalyzer()
	
	// Test JSON-LD script block detection (Issue #7086)
	response := `<script type="application/ld+json">{"@context": "..."}</script>`
	canary := "nucleiXSScanary"
	
	ctx, err := analyzer.AnalyzeContext(response, canary)
	require.NoError(t, err)
	require.Equal(t, ContextJSON, ctx)
}

func TestContextAnalyzer_Srcdoc(t *testing.T) {
	analyzer := NewContextAnalyzer()
	
	// Test srcdoc attribute detection (Issue #7086)
	response := `<iframe srcdoc="<script>alert('XSS')</script>"></iframe>`
	canary := "nucleiXSScanary"
	
	ctx, err := analyzer.AnalyzeContext(response, canary)
	require.NoError(t, err)
	require.Equal(t, ContextSrcdoc, ctx)
}

func TestContextAnalyzer_CaseInsensitiveCanary(t *testing.T) {
	analyzer := NewContextAnalyzer()
	
	// Test case-insensitive canary detection (Issue #7086)
	response := `<div>NUCLEIXSSCANARY</div>`
	canary := "nucleiXSScanary"
	
	ctx, err := analyzer.AnalyzeContext(response, canary)
	require.NoError(t, err)
	require.NotEqual(t, ContextNone, ctx)
}

func TestContextAnalyzer_NormalScript(t *testing.T) {
	analyzer := NewContextAnalyzer()
	
	// Test normal executable script
	response := `<script>alert('XSS')</script>`
	canary := "nucleiXSScanary"
	
	ctx, err := analyzer.AnalyzeContext(response, canary)
	require.NoError(t, err)
	// Should NOT be classified as JSON
	require.NotEqual(t, ContextJSON, ctx)
}

func TestContextAnalyzer_GeoJSONScript(t *testing.T) {
	analyzer := NewContextAnalyzer()
	
	// Test GeoJSON script block detection (Issue #7086)
	response := `<script type="application/geo+json">{"type": "Feature"}</script>`
	canary := "nucleiXSScanary"
	
	ctx, err := analyzer.AnalyzeContext(response, canary)
	require.NoError(t, err)
	require.Equal(t, ContextJSON, ctx)
}
