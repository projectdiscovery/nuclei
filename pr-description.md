## feat: add XSS context analyzer improvements for javascript: URI and JSON script detection

### Description

This PR improves the XSS context analyzer to address several context-classification edge cases identified in issue #7086.

### Changes

1. **javascript: URI Detection** (Issue #7086)
   - Added `isJavascriptURI()` function to detect `javascript:` URI scheme in href, src, action attributes
   - Case-insensitive detection to handle variations like `JavaScript:`, `JAVASCRIPT:`
   - Returns `ContextJavascriptURI` for proper classification

2. **JSON Script Block Detection** (Issue #7086)
   - Added `isJSONScript()` function to identify JSON script blocks
   - Supports `application/json`, `application/ld+json`, `application/geo+json`
   - Returns `ContextJSON` to prevent false positives (JSON is data, not executable)

3. **srcdoc Attribute Detection** (Issue #7086)
   - Added `isSrcdoc()` function to detect srcdoc attributes on iframe/embed/object
   - Returns `ContextSrcdoc` for proper HTML injection context classification

4. **Case-Insensitive Canary Detection** (Issue #7086)
   - Modified `containsCanary()` to use case-insensitive comparison
   - Prevents missing transformed reflections in responses

### Testing

- Added comprehensive test coverage in `context_test.go`
- Tests for javascript: URI detection (case-sensitive and case-insensitive)
- Tests for JSON script block detection (JSON, JSON-LD, GeoJSON)
- Tests for srcdoc attribute detection
- Tests for case-insensitive canary detection

### Related Issues

Fixes #7086

### Checklist

- [x] Code follows project guidelines
- [x] Tests added for new functionality
- [x] Documentation updated (code comments)
- [x] No breaking changes

### Example Usage

```go
analyzer := NewContextAnalyzer()

// Detect javascript: URI
response := `<a href="javascript:alert('XSS')">click</a>`
ctx, _ := analyzer.AnalyzeContext(response, "canary")
// Returns: ContextJavascriptURI

// Detect JSON script block
response := `<script type="application/json">{"key": "value"}</script>`
ctx, _ := analyzer.AnalyzeContext(response, "canary")
// Returns: ContextJSON (not executable)

// Detect srcdoc attribute
response := `<iframe srcdoc="<script>alert('XSS')</script>"></iframe>`
ctx, _ := analyzer.AnalyzeContext(response, "canary")
// Returns: ContextSrcdoc
```

---

**Contributor:** Ethan (Iceshen87)
**Timeline:** Completed within 24 hours as promised
