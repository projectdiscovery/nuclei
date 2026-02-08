# XSS Context Analyzer

The XSS Context Analyzer is an intelligent fuzzing analyzer that detects Cross-Site Scripting (XSS) vulnerabilities by identifying the exact HTML context where user input is reflected and selecting optimal exploitation payloads.

## Overview

Traditional XSS detection tools use blind fuzzing with generic payloads, leading to:
- High false positive rates
- Excessive HTTP requests
- Missed vulnerabilities in complex contexts

This analyzer implements a **Probe-and-Exploit** strategy:

1. **Probe**: Send a canary payload containing XSS-critical characters (`<>'"` + `` ` ``)
2. **Analyze**: Parse HTML response using Go's `html.Tokenizer` to identify exact reflection context
3. **Exploit**: Select context-specific payload or skip if unexploitable (fail-fast)

This approach achieves:
- ✅ Higher accuracy (fewer false positives)
- ✅ Fewer HTTP requests (context-targeted payloads)
- ✅ Better coverage (handles 6+ XSS context types)

## Supported XSS Contexts

| Context | Example | Optimal Payload |
|---------|---------|-----------------|
| **HTML Tag** | `<div>USER_INPUT</div>` | `<script>alert(1)</script>` |
| **Quoted Attribute** | `<input value="USER_INPUT">` | `"><script>alert(1)</script><div x="` |
| **Event Handler** | `<img onclick="USER_INPUT">` | `';alert(1)//` |
| **URL Attribute** | `<a href="USER_INPUT">` | `javascript:alert(1)` |
| **Style Attribute** | `<div style="USER_INPUT">` | `expression(alert(1))` |
| **HTML Comment** | `<!-- USER_INPUT -->` | `--><script>alert(1)</script><!--` |

## Usage

### Basic Template

```yaml
id: xss-fuzzing-example

info:
  name: XSS Detection with Context Analysis
  author: projectdiscovery
  severity: high

http:
  - method: GET
    path:
      - "{{BaseURL}}/?search=[XSS_CANARY]"

    fuzzing:
      - part: query
        type: replace
        mode: single
        fuzz:
          search: "[XSS_CANARY]"

    # Enable XSS context analyzer
    analyzers:
      - name: xss_context
```

### Advanced Configuration

```yaml
http:
  - method: POST
    path:
      - "{{BaseURL}}/search"
    
    body: |
      {"query": "[XSS_CANARY]"}
    
    fuzzing:
      - part: body
        type: replace
        mode: single
        fuzz:
          query: "[XSS_CANARY]"
    
    analyzers:
      - name: xss_context
        parameters:
          # Custom parameters (currently no parameters supported)
          # Future: context_types, payload_depth, etc.
```

### Multiple Injection Points

```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/?search=[XSS_CANARY]&sort=[XSS_CANARY]&page=[XSS_CANARY]"

    fuzzing:
      - part: query
        type: replace
        mode: multiple  # Test all parameters
        fuzz:
          search: "[XSS_CANARY]"
          sort: "[XSS_CANARY]"
          page: "[XSS_CANARY]"

    analyzers:
      - name: xss_context
```

## How It Works

### 1. Probe Phase

The analyzer sends a unique canary payload:

```
xss_[RANDNUM]_<>'"``
```

Example request:
```http
GET /?search=xss_1234_<>'"`` HTTP/1.1
Host: target.com
```

### 2. Analysis Phase

If the canary is reflected, the analyzer:

1. Parses the HTML response using `html.Tokenizer`
2. Identifies all reflection points
3. For each reflection, determines the context:
   - Inside HTML tag?
   - Inside attribute (quoted/unquoted)?
   - Inside event handler?
   - Inside script block?
4. Detects active filters (HTML encoding, quote escaping, etc.)

Example detected context:
```json
{
  "Type": "attribute_quoted",
  "Location": "input value attribute",
  "Payload": "\"><script>alert(1)</script><div x=\"",
  "Filter": "none"
}
```

### 3. Exploit Phase

For each exploitable context:

1. Selects optimal payload for that context type
2. Sends exploit request with context-specific payload
3. Verifies successful exploitation (unescaped payload in response)

Example exploit request:
```http
GET /?search="><script>alert(1)</script><div x=" HTTP/1.1
Host: target.com
```

### 4. Verification

The analyzer checks if the payload appears **unescaped** in the response:

```html
<!-- Exploited (returns true) -->
<input value=""><script>alert(1)</script><div x="">

<!-- Not exploited (returns false) -->
<input value="&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;&lt;div x=&quot;">
```

## Filter Detection

The analyzer automatically detects these common XSS filters:

| Filter | Detection | Behavior |
|--------|-----------|----------|
| **Angle Bracket Removal** | `<>` missing from canary | Skip HTML tag contexts |
| **HTML Entity Encoding** | `&lt;` or `&gt;` present | Skip tag-based payloads |
| **Quote Escaping** | `\'` or `\"` present | Try alternative quotes |

## Output Format

When XSS is detected, the analyzer returns detailed information:

```
[xss_context] XSS vulnerability confirmed
  Context: attribute_quoted
  Location: input value attribute  
  Payload: "><script>alert(1)</script><div x="
  Filters: none
```

This helps security researchers:
- Understand the exact vulnerability context
- Reproduce the issue manually
- Craft better exploitation payloads
- Write accurate vulnerability reports

## Architecture

### Package Structure

```
pkg/fuzz/analyzers/xss/
├── analyzer.go        # Main analyzer implementation
├── analyzer_test.go   # Comprehensive unit tests
└── README.md          # This file
```

### Key Components

#### `Analyzer` struct
Implements the `analyzers.Analyzer` interface with three methods:
- `Name()` - Returns `"xss_context"`
- `ApplyInitialTransformation()` - Handles `[XSS_CANARY]` placeholder
- `Analyze()` - Main detection logic

#### `XSSContext` struct
Represents a detected XSS context:
```go
type XSSContext struct {
    Type     string // e.g., "html_tag", "event_handler"
    Location string // e.g., "div tag", "onclick attribute"
    Payload  string // Context-specific exploit payload
    Filter   string // Detected filters (e.g., "html_encoded")
}
```

#### Core Functions

- `sendProbeRequest()` - Sends initial canary probe
- `detectXSSContexts()` - Parses HTML and finds all reflections
- `classifyAttributeContext()` - Determines specific attribute type
- `detectFilters()` - Identifies active XSS filters
- `exploitContext()` - Attempts exploitation for a context
- `verifyExploitation()` - Confirms successful XSS

## Testing

Run unit tests:

```bash
cd pkg/fuzz/analyzers/xss
go test -v
```

Run tests with coverage:

```bash
go test -v -cover -coverprofile=coverage.out
go tool cover -html=coverage.out
```

## Performance

The analyzer is designed for efficiency:

| Metric | Value |
|--------|-------|
| **Requests per test** | 2-4 (1 probe + 1-3 exploits) |
| **False positive rate** | Low (context verification) |
| **CPU usage** | Minimal (html.Tokenizer is fast) |
| **Memory usage** | ~1-2 MB per request |

Compare to blind fuzzing:
- **Blind XSS fuzzer**: 50-100 requests per parameter
- **XSS Context Analyzer**: 2-4 requests per parameter
- **Reduction**: ~95% fewer requests

## Future Enhancements

Potential improvements for future versions:

1. **DOM XSS Detection**: Detect client-side XSS in JavaScript
2. **Multi-step Contexts**: Handle complex reflection chains
3. **Custom Payload Library**: User-configurable payloads per context
4. **WAF Evasion**: Advanced filter bypass techniques
5. **Severity Scoring**: Rate XSS impact (stored vs reflected)

## References

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS Contexts](https://portswigger.net/web-security/cross-site-scripting/contexts)
- [Go html Package](https://pkg.go.dev/golang.org/x/net/html)
- [Nuclei Fuzzing Documentation](https://docs.projectdiscovery.io/nuclei/fuzzing-overview)

## Contributing

Bug reports, feature requests, and pull requests are welcome!

When contributing, please:
1. Add unit tests for new functionality
2. Update this README with usage examples
3. Follow Go coding conventions
4. Add comprehensive code comments

## License

This package is part of the Nuclei project and is licensed under the MIT License.
