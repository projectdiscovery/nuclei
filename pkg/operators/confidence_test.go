package operators

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/stretchr/testify/require"
)

func matcher(t matchers.MatcherType, part string) *matchers.Matcher {
	return &matchers.Matcher{Type: matchers.MatcherTypeHolder{MatcherType: t}, Part: part}
}

func TestConfidenceTier(t *testing.T) {
	tests := []struct {
		name      string
		operators *Operators
		wantTier  string
	}{
		{
			name:      "nil operators",
			operators: nil,
			wantTier:  ConfidenceLow,
		},
		{
			name:      "no matchers",
			operators: &Operators{},
			wantTier:  ConfidenceLow,
		},
		{
			name: "single status matcher is low",
			operators: &Operators{
				Matchers: []*matchers.Matcher{matcher(matchers.StatusMatcher, "")},
			},
			wantTier: ConfidenceLow,
		},
		{
			name: "redundant status matchers stay low",
			operators: &Operators{
				matchersCondition: matchers.ANDCondition,
				Matchers: []*matchers.Matcher{
					matcher(matchers.StatusMatcher, ""),
					matcher(matchers.StatusMatcher, ""),
					matcher(matchers.StatusMatcher, ""),
				},
			},
			wantTier: ConfidenceLow,
		},
		{
			name: "single body word is medium",
			operators: &Operators{
				Matchers: []*matchers.Matcher{matcher(matchers.WordsMatcher, "body")},
			},
			wantTier: ConfidenceMedium,
		},
		{
			name: "single body regex is medium",
			operators: &Operators{
				Matchers: []*matchers.Matcher{matcher(matchers.RegexMatcher, "body")},
			},
			wantTier: ConfidenceMedium,
		},
		{
			name: "or condition takes strongest matcher",
			operators: &Operators{
				matchersCondition: matchers.ORCondition,
				Matchers: []*matchers.Matcher{
					matcher(matchers.StatusMatcher, ""),
					matcher(matchers.DSLMatcher, "body"),
				},
			},
			wantTier: ConfidenceMedium,
		},
		{
			name: "distinct and-combined classes reach high",
			operators: &Operators{
				matchersCondition: matchers.ANDCondition,
				Matchers: []*matchers.Matcher{
					matcher(matchers.WordsMatcher, "body"),
					matcher(matchers.RegexMatcher, "body"),
				},
			},
			wantTier: ConfidenceHigh,
		},
		{
			name: "status with extractor stays low",
			operators: &Operators{
				Matchers:   []*matchers.Matcher{matcher(matchers.StatusMatcher, "")},
				Extractors: []*extractors.Extractor{{}},
			},
			wantTier: ConfidenceLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, tier := tt.operators.Confidence()
			require.Equal(t, tt.wantTier, tier)
		})
	}
}

// TestConfidenceCorroboration verifies that confidence rises only with distinct
// independent evidence, not with redundant repeats of the same matcher class.
func TestConfidenceCorroboration(t *testing.T) {
	distinct := &Operators{
		matchersCondition: matchers.ANDCondition,
		Matchers: []*matchers.Matcher{
			matcher(matchers.RegexMatcher, "body"),
			matcher(matchers.WordsMatcher, "header"),
			matcher(matchers.StatusMatcher, ""),
		},
	}
	redundant := &Operators{
		matchersCondition: matchers.ANDCondition,
		Matchers: []*matchers.Matcher{
			matcher(matchers.RegexMatcher, "body"),
			matcher(matchers.RegexMatcher, "body"),
			matcher(matchers.RegexMatcher, "body"),
		},
	}
	distinctScore, _ := distinct.Confidence()
	redundantScore, _ := redundant.Confidence()
	require.Greater(t, distinctScore, redundantScore, "distinct evidence classes must outscore redundant repeats of one class")
}

// TestConfidenceNegativeMatcherBonus verifies a negative matcher (explicit
// exclusion of generic/error noise) raises confidence over an identical match
// without it.
func TestConfidenceNegativeMatcherBonus(t *testing.T) {
	base := &Operators{Matchers: []*matchers.Matcher{matcher(matchers.RegexMatcher, "body")}}
	withNegative := &Operators{
		matchersCondition: matchers.ANDCondition,
		Matchers: []*matchers.Matcher{
			matcher(matchers.RegexMatcher, "body"),
			{Type: matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher}, Part: "body", Negative: true},
		},
	}
	baseScore, _ := base.Confidence()
	negScore, _ := withNegative.Confidence()
	require.Greater(t, negScore, baseScore, "negative matcher should add a specificity bonus")
}

// TestConfidenceNegativeMatcherIsNotPositiveEvidence verifies that a negative
// (absence) guard does not contribute its matcher weight as positive evidence.
// A status-only match guarded by "body must not contain an error string" is
// still only a status code match and must stay low confidence.
func TestConfidenceNegativeMatcherIsNotPositiveEvidence(t *testing.T) {
	guarded := &Operators{
		matchersCondition: matchers.ANDCondition,
		Matchers: []*matchers.Matcher{
			matcher(matchers.StatusMatcher, ""),
			{Type: matchers.MatcherTypeHolder{MatcherType: matchers.RegexMatcher}, Part: "body", Negative: true},
		},
	}
	score, tier := guarded.Confidence()
	require.Equal(t, ConfidenceLow, tier, "a strong negative guard must not lift a status-only match out of low")
	require.LessOrEqual(t, score, weightStatusOrSize+negativeMatcherBonus, "negative matcher weight must not count as positive evidence")
}

// TestConfidenceIgnoresInternalMatchers verifies hidden helper matchers used for
// dynamic extraction do not count as user-facing evidence.
func TestConfidenceIgnoresInternalMatchers(t *testing.T) {
	ops := &Operators{
		matchersCondition: matchers.ANDCondition,
		Matchers: []*matchers.Matcher{
			matcher(matchers.StatusMatcher, ""),
			{Type: matchers.MatcherTypeHolder{MatcherType: matchers.DSLMatcher}, Part: "body", Internal: true},
		},
	}
	score, tier := ops.Confidence()
	require.Equal(t, weightStatusOrSize, score, "internal matcher must be ignored, leaving only the status weight")
	require.Equal(t, ConfidenceLow, tier)
}

// neg builds a negative matcher of the given type/part.
func neg(t matchers.MatcherType, part string) *matchers.Matcher {
	return &matchers.Matcher{Type: matchers.MatcherTypeHolder{MatcherType: t}, Part: part, Negative: true}
}

// TestConfidenceRealWorldScenarios pins the score band and tier for matcher
// compositions that mirror real nuclei templates, so the scorer stays sensible
// as it evolves.
func TestConfidenceRealWorldScenarios(t *testing.T) {
	tests := []struct {
		name      string
		operators *Operators
		minScore  int
		maxScore  int
		wantTier  string
	}{
		{
			name: "host-up status probe",
			operators: &Operators{
				Matchers: []*matchers.Matcher{matcher(matchers.StatusMatcher, "")},
			},
			minScore: 1, maxScore: weightStatusOrSize, wantTier: ConfidenceLow,
		},
		{
			name: "tech detection single header banner",
			operators: &Operators{
				Matchers: []*matchers.Matcher{matcher(matchers.WordsMatcher, "header")},
			},
			minScore: weightWordHeader, maxScore: weightWordHeader, wantTier: ConfidenceLow,
		},
		{
			name: "exposed panel title word",
			operators: &Operators{
				Matchers: []*matchers.Matcher{matcher(matchers.WordsMatcher, "body")},
			},
			minScore: weightWordContent, maxScore: weightWordContent, wantTier: ConfidenceMedium,
		},
		{
			name: "favicon hash dsl",
			operators: &Operators{
				Matchers: []*matchers.Matcher{matcher(matchers.DSLMatcher, "")},
			},
			minScore: weightStrongContent, maxScore: weightStrongContent, wantTier: ConfidenceMedium,
		},
		{
			name: "cve body regex and status with extractor",
			operators: &Operators{
				matchersCondition: matchers.ANDCondition,
				Matchers: []*matchers.Matcher{
					matcher(matchers.RegexMatcher, "body"),
					matcher(matchers.StatusMatcher, ""),
				},
				Extractors: []*extractors.Extractor{{}},
			},
			minScore: confidenceHighThreshold, maxScore: ConfidenceCertain, wantTier: ConfidenceHigh,
		},
		{
			name: "strong body match guarded by negative error page",
			operators: &Operators{
				matchersCondition: matchers.ANDCondition,
				Matchers: []*matchers.Matcher{
					matcher(matchers.WordsMatcher, "body"),
					neg(matchers.WordsMatcher, "body"),
				},
			},
			minScore: weightWordContent, maxScore: weightWordContent + negativeMatcherBonus, wantTier: ConfidenceMedium,
		},
		{
			name: "fingerprint or any of several strong signals",
			operators: &Operators{
				matchersCondition: matchers.ORCondition,
				Matchers: []*matchers.Matcher{
					matcher(matchers.RegexMatcher, "body"),
					matcher(matchers.DSLMatcher, "body"),
					matcher(matchers.WordsMatcher, "header"),
				},
			},
			minScore: weightStrongContent, maxScore: weightStrongContent, wantTier: ConfidenceMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, tier := tt.operators.Confidence()
			require.GreaterOrEqual(t, score, tt.minScore, "score below expected band")
			require.LessOrEqual(t, score, tt.maxScore, "score above expected band")
			require.Equal(t, tt.wantTier, tier)
		})
	}
}

// TestConfidenceMultiPatternBonus verifies a single matcher requiring several
// distinct content patterns (condition: and) outscores the same matcher with a
// single pattern, while a broad any-of (or) matcher gets no bonus.
func TestConfidenceMultiPatternBonus(t *testing.T) {
	single := &Operators{Matchers: []*matchers.Matcher{
		{Type: matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher}, Part: "body", Words: []string{"a"}},
	}}
	multiAnd := &Operators{Matchers: []*matchers.Matcher{
		{Type: matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher}, Part: "body", Words: []string{"a", "b", "c"}, Condition: "and"},
	}}
	multiOr := &Operators{Matchers: []*matchers.Matcher{
		{Type: matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher}, Part: "body", Words: []string{"a", "b", "c"}, Condition: "or"},
	}}
	matchAll := &Operators{Matchers: []*matchers.Matcher{
		{Type: matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher}, Part: "body", Words: []string{"a", "b"}, MatchAll: true},
	}}

	singleScore, _ := single.Confidence()
	multiAndScore, _ := multiAnd.Confidence()
	multiOrScore, _ := multiOr.Confidence()
	matchAllScore, _ := matchAll.Confidence()

	require.Greater(t, multiAndScore, singleScore, "all-of multi-pattern matcher should outscore single pattern")
	require.Equal(t, singleScore, multiOrScore, "any-of multi-pattern matcher should not earn the bonus")
	require.Greater(t, matchAllScore, singleScore, "match-all matcher should earn the multi-pattern bonus")
}

// TestConfidenceDSLWeakOnly verifies a dsl matcher that only inspects status or
// size metadata is scored as weak as a status match, while a dsl that inspects
// the body keeps strong-content reliability.
func TestConfidenceDSLWeakOnly(t *testing.T) {
	weak := &Operators{Matchers: []*matchers.Matcher{
		{Type: matchers.MatcherTypeHolder{MatcherType: matchers.DSLMatcher}, DSL: []string{"status_code == 200"}},
	}}
	weakCombo := &Operators{Matchers: []*matchers.Matcher{
		{Type: matchers.MatcherTypeHolder{MatcherType: matchers.DSLMatcher}, DSL: []string{"status_code == 200 && content_length > 10"}},
	}}
	strong := &Operators{Matchers: []*matchers.Matcher{
		{Type: matchers.MatcherTypeHolder{MatcherType: matchers.DSLMatcher}, DSL: []string{"contains(body, 'SecretMarker') && status_code == 200"}},
	}}

	weakScore, weakTier := weak.Confidence()
	weakComboScore, _ := weakCombo.Confidence()
	strongScore, strongTier := strong.Confidence()

	require.Equal(t, weightStatusOrSize, weakScore, "metadata-only dsl must score as a status match")
	require.Equal(t, ConfidenceLow, weakTier)
	require.Equal(t, weightStatusOrSize, weakComboScore, "status+size-only dsl is still metadata inference")
	require.Equal(t, weightStrongContent, strongScore, "body-inspecting dsl keeps strong-content weight")
	require.Equal(t, ConfidenceMedium, strongTier)
}

func TestScoreToTier(t *testing.T) {
	require.Equal(t, ConfidenceLow, ScoreToTier(0))
	require.Equal(t, ConfidenceLow, ScoreToTier(confidenceMediumThreshold-1))
	require.Equal(t, ConfidenceMedium, ScoreToTier(confidenceMediumThreshold))
	require.Equal(t, ConfidenceHigh, ScoreToTier(confidenceHighThreshold))
	require.Equal(t, ConfidenceHigh, ScoreToTier(ConfidenceCertain))
}
