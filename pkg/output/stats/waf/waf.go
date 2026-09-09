package waf

import (
	_ "embed"
	"encoding/json"
	"log"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxLiteralPrefilterClauses          = 64
	maxLiteralPrefilterNeedlesPerClause = 32
)

type WafDetector struct {
	wafs           map[string]waf
	regexCache     map[string]*regexp.Regexp
	prefilterCache map[string]literalPrefilter
}

// DetectionStats reports how much of the WAF regex set was evaluated for one
// response. A prefilter skip means the regex could not possibly match because
// a literal required by every matching path was absent.
type DetectionStats struct {
	RegexEvaluations int
	PrefilterSkips   int
}

type literalNeedle struct {
	value    string
	foldCase bool
}

type literalClause []literalNeedle

type literalPrefilter struct {
	clauses       []literalClause
	needsFoldCase bool
}

func (p literalPrefilter) allows(content string) bool {
	var foldedContent string
	if p.needsFoldCase {
		foldedContent = canonicalFoldString(content)
	}
	return p.allowsWithFoldedContent(content, foldedContent)
}

func (p literalPrefilter) allowsWithFoldedContent(content, foldedContent string) bool {
	for _, clause := range p.clauses {
		matches := true
		for _, needle := range clause {
			haystack := content
			if needle.foldCase {
				haystack = foldedContent
			}
			if !strings.Contains(haystack, needle.value) {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

// waf represents a web application firewall definition
type waf struct {
	Company string `json:"company"`
	Name    string `json:"name"`
	Regex   string `json:"regex"`
}

// wafData represents the root JSON structure
type wafData struct {
	WAFs map[string]waf `json:"wafs"`
}

//go:embed regexes.json
var wafContentRegexes string

func NewWafDetector() *WafDetector {
	var data wafData
	if err := json.Unmarshal([]byte(wafContentRegexes), &data); err != nil {
		log.Printf("could not unmarshal waf content regexes: %s", err)
	}

	store := &WafDetector{
		wafs:           data.WAFs,
		regexCache:     make(map[string]*regexp.Regexp),
		prefilterCache: make(map[string]literalPrefilter),
	}

	for id, waf := range store.wafs {
		if waf.Regex == "" {
			continue
		}
		compiled, err := regexp.Compile(waf.Regex)
		if err != nil {
			log.Printf("invalid WAF regex for %s: %v", id, err)
			continue
		}
		store.regexCache[id] = compiled
		if prefilter, ok := buildLiteralPrefilter(waf.Regex); ok {
			store.prefilterCache[id] = prefilter
		}
	}
	return store
}

func (d *WafDetector) DetectWAF(content string) (string, bool) {
	id, matched, _ := d.DetectWAFWithStats(content)
	return id, matched
}

// DetectWAFWithStats detects a WAF and reports the amount of regex work done.
// The original compiled regex remains the source of truth. A regex is skipped
// only when a conservatively derived, required literal is absent.
func (d *WafDetector) DetectWAFWithStats(content string) (string, bool, DetectionStats) {
	var stats DetectionStats
	if d == nil || d.regexCache == nil {
		return "", false, stats
	}

	var foldedContent string
	foldedContentReady := false
	for id, regex := range d.regexCache {
		if regex == nil {
			continue
		}
		if prefilter, ok := d.prefilterCache[id]; ok {
			if prefilter.needsFoldCase && !foldedContentReady {
				foldedContent = canonicalFoldString(content)
				foldedContentReady = true
			}
			if !prefilter.allowsWithFoldedContent(content, foldedContent) {
				stats.PrefilterSkips++
				continue
			}
		}
		stats.RegexEvaluations++
		if regex.MatchString(content) {
			return id, true, stats
		}
	}
	return "", false, stats
}

func buildLiteralPrefilter(expression string) (literalPrefilter, bool) {
	parsed, err := syntax.Parse(expression, syntax.Perl)
	if err != nil {
		return literalPrefilter{}, false
	}
	clauses, ok := requiredLiteralClauses(parsed.Simplify())
	if !ok {
		return literalPrefilter{}, false
	}

	deduplicated := make([]literalClause, 0, len(clauses))
	needsFoldCase := false
	for _, clause := range clauses {
		clause = deduplicateLiteralClause(clause)
		if len(clause) == 0 || len(clause) > maxLiteralPrefilterNeedlesPerClause {
			return literalPrefilter{}, false
		}
		for _, needle := range clause {
			if needle.value == "" {
				return literalPrefilter{}, false
			}
			needsFoldCase = needsFoldCase || needle.foldCase
		}
		if !containsLiteralClause(deduplicated, clause) {
			deduplicated = append(deduplicated, clause)
		}
	}
	if len(deduplicated) == 0 || len(deduplicated) > maxLiteralPrefilterClauses {
		return literalPrefilter{}, false
	}
	return literalPrefilter{clauses: deduplicated, needsFoldCase: needsFoldCase}, true
}

// requiredLiteralClauses returns an OR-set of AND-clauses with this invariant:
// whenever expression matches, every literal in at least one returned clause
// occurs in the input. Unsupported or ambiguous expressions fall back to the
// original regex by returning false.
func requiredLiteralClauses(expression *syntax.Regexp) ([]literalClause, bool) {
	if expression == nil {
		return nil, false
	}

	switch expression.Op {
	case syntax.OpLiteral:
		if len(expression.Rune) == 0 {
			return nil, false
		}
		for _, value := range expression.Rune {
			if value == utf8.RuneError {
				return nil, false
			}
		}
		foldCase := expression.Flags&syntax.FoldCase != 0
		value := string(expression.Rune)
		if foldCase {
			value = canonicalFoldString(value)
		}
		return []literalClause{{{value: value, foldCase: foldCase}}}, true

	case syntax.OpCapture:
		if len(expression.Sub) != 1 {
			return nil, false
		}
		return requiredLiteralClauses(expression.Sub[0])

	case syntax.OpPlus:
		if len(expression.Sub) != 1 {
			return nil, false
		}
		return requiredLiteralClauses(expression.Sub[0])

	case syntax.OpRepeat:
		if expression.Min < 1 || len(expression.Sub) != 1 {
			return nil, false
		}
		return requiredLiteralClauses(expression.Sub[0])

	case syntax.OpConcat:
		clauses := []literalClause{{}}
		found := false
		for _, child := range expression.Sub {
			candidate, ok := requiredLiteralClauses(child)
			if !ok {
				continue
			}
			found = true
			if len(clauses) > maxLiteralPrefilterClauses/len(candidate) {
				return nil, false
			}
			combined := make([]literalClause, 0, len(clauses)*len(candidate))
			for _, currentClause := range clauses {
				for _, candidateClause := range candidate {
					if len(currentClause)+len(candidateClause) > maxLiteralPrefilterNeedlesPerClause {
						return nil, false
					}
					merged := make(literalClause, 0, len(currentClause)+len(candidateClause))
					merged = append(merged, currentClause...)
					merged = append(merged, candidateClause...)
					combined = append(combined, merged)
				}
			}
			clauses = combined
		}
		if !found {
			return nil, false
		}
		return clauses, true

	case syntax.OpAlternate:
		var clauses []literalClause
		for _, child := range expression.Sub {
			candidate, ok := requiredLiteralClauses(child)
			if !ok {
				return nil, false
			}
			if len(clauses)+len(candidate) > maxLiteralPrefilterClauses {
				return nil, false
			}
			clauses = append(clauses, candidate...)
		}
		if len(clauses) == 0 {
			return nil, false
		}
		return clauses, true

	default:
		return nil, false
	}
}

func deduplicateLiteralClause(clause literalClause) literalClause {
	deduplicated := make(literalClause, 0, len(clause))
	for _, needle := range clause {
		found := false
		for _, existing := range deduplicated {
			if existing == needle {
				found = true
				break
			}
		}
		if !found {
			deduplicated = append(deduplicated, needle)
		}
	}
	return deduplicated
}

func containsLiteralClause(clauses []literalClause, candidate literalClause) bool {
	for _, clause := range clauses {
		if len(clause) != len(candidate) {
			continue
		}
		equal := true
		for index := range clause {
			if clause[index] != candidate[index] {
				equal = false
				break
			}
		}
		if equal {
			return true
		}
	}
	return false
}

func canonicalFoldString(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	for index := 0; index < len(value); {
		current := value[index]
		if current < utf8.RuneSelf {
			if current >= 'a' && current <= 'z' {
				current -= 'a' - 'A'
			}
			builder.WriteByte(current)
			index++
			continue
		}
		decoded, size := utf8.DecodeRuneInString(value[index:])
		builder.WriteRune(canonicalFoldRune(decoded))
		index += size
	}
	return builder.String()
}

func canonicalFoldRune(value rune) rune {
	canonical := value
	for folded := unicode.SimpleFold(value); folded != value; folded = unicode.SimpleFold(folded) {
		if folded < canonical {
			canonical = folded
		}
	}
	return canonical
}

func (d *WafDetector) GetWAF(id string) (waf, bool) {
	waf, ok := d.wafs[id]
	return waf, ok
}
