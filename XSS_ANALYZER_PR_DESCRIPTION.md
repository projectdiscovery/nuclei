# XSS Context Analyzer Implementation

## Overview

This PR implements an intelligent XSS Context Analyzer for the nuclei fuzzer that detects Cross-Site Scripting vulnerabilities using context-aware analysis instead of blind fuzzing.

## Problem Statement

Traditional XSS detection tools suffer from:
- **High false positive rates** - generic payloads trigger WAF/filters
- **Excessive HTTP requests** - 50-100 requests per parameter with blind fuzzing  
- **Missed vulnerabilities** - wrong payload for the context (e.g., trying `<script>` in event handlers)

## Solution: Probe-and-Exploit Strategy

This analyzer implements a three-phase approach:

### 1. Probe Phase
Send a unique canary payload containing all XSS-critical characters:
```
xss_[RAND NUM]_<>'"``
```

### 2. Analysis Phase
- Parse HTML response using `html.Tokenizer`
- Identify exact reflection context (HTML tag, attribute, event handler, URL, etc.)
- Detect active filters (HTML encoding, quote escaping, angle bracket removal)

### 3. Exploit Phase
- Select optimal payload for detected context
- Send targeted exploit request
- Verify successful exploitation (unescaped payload in response)

## Supported XSS Contexts

| Context | Detection | Optimal Payload |
|---------|-----------|-----------------|
| HTML Tag | `<div>USER_INPUT</div>` | `<script>alert(1)</script>` |
| Quoted Attribute | `<input value="USER_INPUT">` | `"><script>alert(1)</script><div x="` |
| Event Handler | `<img onclick="USER_INPUT">` | `';alert(1)//` |
| URL Attribute | `<a href="USER_INPUT">` | `javascript:alert(1)` |
| Style Attribute | `<div style="USER_INPUT">` | `expression(alert(1))` |
| HTML Comment | `<!-- USER_INPUT -->` | `--><script>alert(1)</script><!--` |

## Performance Benefits

| Metric | Blind Fuzzing | XSS Context Analyzer | Improvement |
|--------|---------------|----------------------|-------------|
| Requests per test | 50-100 | 2-4 | **95% reduction** |
| False positive rate | High | Low | Context verification |
| Context coverage | Limited | 6+ types | Comprehensive |

## Implementation Details

### File Structure
```
pkg/fuzz/analyzers/xss/
├── analyzer.go              # Main implementation (350 lines)
├── analyzer_test.go         # Comprehensive unit tests (280 lines)
├── README.md                # Documentation (350 lines)
└── examples/
    └── basic-xss-fuzzing.yaml  # Usage example
```

### Code Quality
- ✅ **Comprehensive comments** - Every function, struct, and algorithm documented
- ✅ **Unit tests** - 13 test cases covering all contexts and edge cases
- ✅ **Error handling** - Proper error wrapping and logging
- ✅ **Documentation** - 350+ line README with examples and architecture details
- ✅ **Go conventions** - Follows nuclei's existing analyzer pattern

### Key Components

#### Analyzer struct
Implements `analyzers.Analyzer` interface:
```go
type Analyzer struct{}

func (a *Analyzer) Name() string
func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string  
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error)
```

#### XSSContext struct
Represents a detected XSS context:
```go
type XSSContext struct {
    Type     string // e.g., "html_tag", "event_handler"
    Location string // e.g., "div tag", "onclick attribute"  
    Payload  string // Context-specific exploit payload
    Filter   string // Detected filters
}
```

## Usage Example

```yaml
id: xss-detection

info:
  name: XSS Vulnerability Detection
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

    analyzers:
      - name: xss_context  # Enable XSS context analyzer
```

## Testing

All unit tests pass:
```bash
cd pkg/fuzz/analyzers/xss
go test -v
```

Test coverage:
- ✅ Canary transformation
- ✅ HTML tag context detection
- ✅ Attribute context classification  
- ✅ Event handler detection
- ✅ URL attribute detection
- ✅ Comment context detection
- ✅ Filter detection (HTML encoding, quote escaping, etc.)
- ✅ Exploitation verification
- ✅ No-reflection scenario
- ✅ Integration with HTTP client

## Integration

The analyzer follows the existing pattern from `time_delay` analyzer:

1. **Registration** - Auto-registers on init via `analyzers.RegisterAnalyzer()`
2. **Placeholder** - Uses `[XSS_CANARY]` similar to `[SLEEPTIME]`  
3. **Options** - Uses standard `analyzers.Options` struct
4. **Return format** - Returns `(matched bool, reason string, err error)`

No breaking changes to existing code.

## Future Enhancements

Potential improvements for follow-up PRs:
- DOM XSS detection (client-side JavaScript analysis)
- Multi-step reflection chains
- Custom payload libraries
- WAF evasion techniques
- Severity scoring (stored vs reflected XSS)

## References

- OWASP XSS Prevention Cheat Sheet
- PortSwigger XSS Contexts Guide  
- Go html.Tokenizer documentation
- ZAP Active Scanner (time_delay algorithm inspiration)

## Closes

Closes #5838

/claim #5838

---

**Summary**: Production-ready XSS Context Analyzer with comprehensive documentation, unit tests, and 95% request reduction compared to blind fuzzing.
