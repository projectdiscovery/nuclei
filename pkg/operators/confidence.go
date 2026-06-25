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
)

// isContentPart reports whether a matcher part inspects response content (body
// or full response) rather than just status/headers. Content matches are harder
// to trigger by accident than metadata matches.
func isContentPart(part string) bool {
	switch strings.ToLower(part) {
	case "", "body", "all", "response", "raw", "data":
		return true
	default:
		return false
	}
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
	default: // regex, binary, dsl, xpath
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

	classes := make(map[evidenceClass]struct{})
	best := 0
	hasNegative := false
	for _, m := range operators.Matchers {
		if m == nil || m.Internal {
			// internal matchers feed dynamic extraction chains and are hidden
			// from output, so they are not evidence for the user-facing match.
			continue
		}
		if m.Negative {
			hasNegative = true
		}
		class, weight := classify(m)
		classes[class] = struct{}{}
		if weight > best {
			best = weight
		}
	}
	if best == 0 {
		return 0, ConfidenceLow
	}

	score := best
	// Independent corroboration raises confidence, but only when every matcher
	// must hold (AND) and only across distinct evidence classes.
	if operators.matchersCondition == matchers.ANDCondition && len(classes) > 1 {
		bonus := (len(classes) - 1) * corroborationPerClass
		if bonus > corroborationCap {
			bonus = corroborationCap
		}
		score += bonus
	}
	if hasNegative {
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
