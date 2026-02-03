package honeypot

// Honeypot Detection Package
//
// This package implements a non-breaking, post-processing honeypot detector
// that identifies hosts matching an unusually large number of unrelated templates.
//
// ## Design Principles
//
// 1. **Conservative Detection**: Uses multi-signal analysis to minimize false positives
// 2. **Non-Breaking**: Warn-only by default; does not block findings
// 3. **Isolated**: Detection logic is self-contained in pkg/honeypot
// 4. **Transparent**: Easy to integrate with existing output pipeline
//
// ## Detection Logic
//
// A host is flagged as a honeypot when it exhibits multiple indicators:
//
// 1. **High Match Count** (≥20 templates)
//    - Many unrelated templates match on the same host
//    - Indicates unusual response patterns
//
// 2. **High Category Diversity** (≥6 distinct categories)
//    - Matches span unrelated technology categories
//    - E.g., Cisco, Fortinet, Apache, PHP, Tomcat, MySQL
//    - Real systems typically focus on one or two categories
//
// 3. **High Response Reuse** (≥80% identical bodies)
//    - Hash-based similarity detection
//    - Honeypots often return static responses
//    - Same response matches many different templates
//
// 4. **Technology Stack Conflicts**
//    - Incompatible technologies matched (e.g., Cisco + Fortinet)
//    - Should never appear on same real system
//    - Strong indicator of honeypot behavior
//
// ## Architecture
//
// The package consists of:
//
// - **Detector**: Core detection logic
//   - recordMatch(): Aggregates template match data per host
//   - IsHoneypot(): Analyzes collected metrics
//   - Multi-threaded safe with RWMutex locks
//
// - **Middleware**: Output pipeline integration
//   - Wraps output.Writer interface
//   - Intercepts ResultEvent before writing
//   - Emits warnings based on detection mode
//   - Maintains transparency: all results written by default
//
// - **DetectionMode**: Configurable behavior
//   - "warn": Emit warnings only (default)
//   - "tag": Mark flagged results (metadata flag)
//   - "suppress": Filter out flagged results (destructive)
//
// ## Integration Points
//
// 1. **CLI Flag**: --honeypot-detect (flag) in cmd/nuclei/main.go
// 2. **Options**: HoneypotDetect field in pkg/types/types.go
// 3. **Runner**: Integration in internal/runner/runner.go
//    - Wraps output writer with Middleware
//    - Only if HoneypotDetect option is set
// 4. **Output**: Results flow through middleware.Write()
//    - Detection runs on each match
//    - Warnings emitted asynchronously
//
// ## Example Usage
//
//    nuclei -u example.com -t nuclei-templates/ --honeypot-detect warn
//
// Output:
//
//    [HONEYPOT WARNING]
//    Host: http://example.com
//    Reason:
//      - 43 templates matched
//      - 9 unrelated categories
//      - 91% identical response bodies
//    Results may be unreliable.
//
// ## Testing
//
// Comprehensive unit tests in detector_test.go cover:
//
// - Normal vulnerable hosts (NOT flagged)
// - High match count with same category (NOT flagged)
// - Mixed categories with reused responses (flagged)
// - Disabled detection (NOT flagged)
// - CDN/WAF edge cases (carefully NOT flagged)
// - Conflicting tech stack detection (flagged)
// - Empty hosts (NOT flagged)
// - Low match count (NOT flagged)
// - Report formatting
// - Concurrent recording (race-safe)
//
// ## Future Enhancements
//
// - Machine learning classification (beyond heuristics)
// - IP reputation integration (threat intelligence)
// - Geographic/ASN-based anomaly detection
// - Configurable thresholds (not hard-coded)
// - Persistent honeypot database (learn from past scans)
// - Integration with issue tracking (auto-close honeypot issues)
