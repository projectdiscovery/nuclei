package operators

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
)

// Confidence tiers reported alongside a result. They express how reliable the
// detection is, independent of severity (how bad the issue is). The split
// follows the Burp "tentative/firm/certain" and OpenVAS QoD models.
const (
	ConfidenceLow    = "low"
	ConfidenceMedium = "medium"
	ConfidenceHigh   = "high"
)

// confidence is reported on a 0-100 scale modelled on OpenVAS "Quality of
// Detection" (QoD). Tier thresholds align with the scale; OpenVAS uses 70 as its
// default trustworthy cutoff, which sits inside the medium band here.
const (
	confidenceMediumThreshold = 50
	confidenceHighThreshold   = 80
	// ConfidenceCertain is the score for out-of-band confirmed detections
	// (e.g. an interactsh interaction): unambiguous proof, so the maximum.
	ConfidenceCertain = 100
	// ConfidenceCatchAll is the clamped score for matches that also fire against
	// the host's catch-all baseline: a strong false-positive signal.
	ConfidenceCatchAll = 10
)

// Base reliability of each evidence class. The ordering follows the black-box
// scanner literature and QoD detection methods: matching on a status code or
// response size is the most false-positive prone form of inference (an HTTP 500
// can be any error, a banner can be backported), matching content with a
// word is moderate, and matching content with a regex/dsl/binary/xpath is the
// strongest in-band signal. Out-of-band confirmation (handled by the caller)
// outranks all of these.
const (
	weightStatusOrSize  = 25
	weightWordHeader    = 45
	weightStrongHeader  = 55
	weightWordContent   = 60
	weightStrongContent = 75

	// corroboration adds confidence only across DISTINCT, AND-combined evidence
	// classes (independent confirmation), with diminishing returns.
	corroborationPerClass = 10
	corroborationCap      = 20
	negativeMatcherBonus  = 5
	extractorBonus        = 3
	// multiPatternBonus rewards a single matcher that requires several distinct
	// patterns to all be present (condition: and / match-all). Needing many
	// independent strings is far harder to trigger by accident than one.
	multiPatternBonus = 8
)

// dslWeakIndicators are DSL variables that only inspect response metadata.
// dslContentIndicators signal that a DSL expression actually inspects the
// response body/headers, which is a far stronger detection method.
var (
	dslWeakIndicators    = []string{"status_code", "content_length", "duration"}
	dslContentIndicators = []string{"body", "header", "all_headers", "contains", "regex", "len(", "tolower", "toupper", "title", "hash", "md5", "sha", "base64", "html", "response", "data"}
)

// dslWeakOnly reports whether a DSL matcher only inspects status/size metadata.
// Such a matcher is a "strong" matcher type but carries status-level reliability
// (an HTTP 500 can be any error), so it must not be scored as body evidence.
func dslWeakOnly(m *matchers.Matcher) bool {
	if len(m.DSL) == 0 {
		return false
	}
	weak := false
	for _, expr := range m.DSL {
		e := strings.ToLower(expr)
		for _, c := range dslContentIndicators {
			if strings.Contains(e, c) {
				return false
			}
		}
		for _, w := range dslWeakIndicators {
			if strings.Contains(e, w) {
				weak = true
			}
		}
	}
	return weak
}

// requiresAllPatterns reports whether every pattern in the matcher must be
// present (condition: and or match-all), rather than any single one.
func requiresAllPatterns(m *matchers.Matcher) bool {
	return m.MatchAll || strings.EqualFold(m.Condition, "and")
}

// patternCount counts the independent content patterns a matcher carries.
// Status/size codes are intentionally excluded: matching any of several status
// codes broadens rather than narrows a match.
func patternCount(m *matchers.Matcher) int {
	return len(m.Words) + len(m.Regex) + len(m.Binary) + len(m.DSL) + len(m.XPath)
}

// metadataParts are response parts that carry weak, false-positive-prone signal
// across every protocol: protocol metadata (status/size/rcode/duration), HTTP
// response headers (the generic part and the common header fields used directly)
// and request-side echoes. Matching these is more backportable / accidental than
// matching real response content. Everything not listed here (response bodies,
// DNS answer/ns/extra sections, TLS certificate fields, command stdout/stderr,
// websocket/whois/javascript payloads, ...) is treated as content, so non-HTTP
// protocols are scored on the strength of what they actually inspect.
var metadataParts = map[string]struct{}{
	"header": {}, "all_headers": {}, "headers": {},
	"status": {}, "status_code": {}, "size": {}, "content_length": {}, "duration": {},
	"rcode": {},
	"request": {}, "host": {}, "ip": {}, "port": {}, "matched": {}, "type": {},
	// common HTTP response header fields that templates match on directly
	"content_type": {}, "content-type": {}, "server": {}, "location": {},
	"set_cookie": {}, "set-cookie": {}, "www_authenticate": {}, "www-authenticate": {},
	"x_powered_by": {}, "x-powered-by": {}, "cache_control": {}, "cache-control": {},
}

// stripIndexSuffix removes the _<n> suffix that flow / multi-request templates
// append to response parts (body_2, header_3, content_type_2) so they classify
// the same as their base part.
func stripIndexSuffix(p string) string {
	i := strings.LastIndexByte(p, '_')
	if i <= 0 || i == len(p)-1 {
		return p
	}
	for j := i + 1; j < len(p); j++ {
		if p[j] < '0' || p[j] > '9' {
			return p
		}
	}
	return p[:i]
}

// isContentPart reports whether a matcher part inspects response content rather
// than protocol metadata or headers. Content is the default: only the known
// weak metadata parts are excluded. Content matches are harder to trigger by
// accident, so they carry higher confidence weight.
func isContentPart(part string) bool {
	p := stripIndexSuffix(strings.ToLower(strings.TrimSpace(part)))
	_, meta := metadataParts[p]
	return !meta
}

// evidenceClass identifies an independent line of evidence. Corroboration is
// rewarded across distinct classes, not redundant repeats of the same weak
// matcher, so three status matchers do not masquerade as strong evidence.
type evidenceClass struct {
	kind    string
	content bool
}

// classify returns the evidence class and base reliability weight for a matcher.
func classify(m *matchers.Matcher) (evidenceClass, int) {
	content := isContentPart(m.Part)
	switch m.Type.MatcherType {
	case matchers.StatusMatcher:
		return evidenceClass{kind: "status"}, weightStatusOrSize
	case matchers.SizeMatcher:
		return evidenceClass{kind: "size"}, weightStatusOrSize
	case matchers.WordsMatcher:
		if content {
			return evidenceClass{kind: "word", content: true}, weightWordContent
		}
		return evidenceClass{kind: "word"}, weightWordHeader
	case matchers.DSLMatcher:
		if dslWeakOnly(m) {
			// a dsl that only checks status_code/content_length is metadata
			// inference, not body evidence, despite being a "strong" type.
			return evidenceClass{kind: "status"}, weightStatusOrSize
		}
		if content {
			return evidenceClass{kind: "strong", content: true}, weightStrongContent
		}
		return evidenceClass{kind: "strong"}, weightStrongHeader
	default: // regex, binary, xpath
		if content {
			return evidenceClass{kind: "strong", content: true}, weightStrongContent
		}
		return evidenceClass{kind: "strong"}, weightStrongHeader
	}
}

// Confidence computes a static, deterministic detection-confidence score (0-100)
// and tier from the template's matcher composition. It rewards strong matcher
// techniques, content-level matching, independent corroboration across distinct
// AND-combined evidence classes and negative matchers, while capping redundant
// weak matchers. Hidden (internal) helper matchers are ignored. The score is
// derived from the template definition alone and sends no additional traffic;
// out-of-band confirmation is folded in by the caller.
func (operators *Operators) Confidence() (int, string) {
	if operators == nil || len(operators.Matchers) == 0 {
		// extraction-only or matcher-less detections carry the weakest signal
		return 0, ConfidenceLow
	}

	// positive (direct) evidence and negative (absence) evidence are tracked
	// separately: a negative matcher behaves as a false-positive guard when it
	// accompanies positive evidence, but is the detection itself when it stands
	// alone (e.g. token-spray validity checks, "setting reverted" CVE steps).
	classes := make(map[evidenceClass]struct{})
	best := 0
	hasMultiPattern := false

	negClasses := make(map[evidenceClass]struct{})
	negBest := 0
	negMultiPattern := false
	negCount := 0

	for _, m := range operators.Matchers {
		if m == nil || m.Internal {
			// internal matchers feed dynamic extraction chains and are hidden
			// from output, so they are not evidence for the user-facing match.
			continue
		}
		class, weight := classify(m)
		// a single matcher that requires several distinct content patterns to
		// all hold is highly specific. Status/size and weak-dsl matchers are
		// excluded (weight gate) since matching any of several codes broadens.
		multi := weight > weightStatusOrSize && requiresAllPatterns(m) && patternCount(m) > 1
		if m.Negative {
			negCount++
			negClasses[class] = struct{}{}
			if weight > negBest {
				negBest = weight
			}
			if multi {
				negMultiPattern = true
			}
			continue
		}
		classes[class] = struct{}{}
		if weight > best {
			best = weight
		}
		if multi {
			hasMultiPattern = true
		}
	}

	// a negative matcher is a guard only when it backs up positive evidence.
	negativeAsGuard := best > 0 && negCount > 0
	if best == 0 {
		// no positive evidence: the absence assertions are the detection. Score
		// them by their own weight rather than discarding the match entirely.
		best, classes, hasMultiPattern = negBest, negClasses, negMultiPattern
	}
	if best == 0 {
		return 0, ConfidenceLow
	}

	score := best
	if hasMultiPattern {
		score += multiPatternBonus
	}
	// Independent corroboration raises confidence, but only when every matcher
	// must hold (AND) and only across distinct evidence classes.
	if operators.matchersCondition == matchers.ANDCondition && len(classes) > 1 {
		bonus := (len(classes) - 1) * corroborationPerClass
		if bonus > corroborationCap {
			bonus = corroborationCap
		}
		score += bonus
	}
	if negativeAsGuard {
		score += negativeMatcherBonus
	}
	if len(operators.Extractors) > 0 {
		score += extractorBonus
	}
	if score > ConfidenceCertain {
		score = ConfidenceCertain
	}
	return score, ScoreToTier(score)
}

// ScoreToTier maps a 0-100 confidence score to its tier.
func ScoreToTier(score int) string {
	switch {
	case score >= confidenceHighThreshold:
		return ConfidenceHigh
	case score >= confidenceMediumThreshold:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}
