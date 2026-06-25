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
	withNegative := &Operators{Matchers: []*matchers.Matcher{
		{Type: matchers.MatcherTypeHolder{MatcherType: matchers.RegexMatcher}, Part: "body", Negative: true},
	}}
	baseScore, _ := base.Confidence()
	negScore, _ := withNegative.Confidence()
	require.Greater(t, negScore, baseScore, "negative matcher should add a specificity bonus")
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

func TestScoreToTier(t *testing.T) {
	require.Equal(t, ConfidenceLow, ScoreToTier(0))
	require.Equal(t, ConfidenceLow, ScoreToTier(confidenceMediumThreshold-1))
	require.Equal(t, ConfidenceMedium, ScoreToTier(confidenceMediumThreshold))
	require.Equal(t, ConfidenceHigh, ScoreToTier(confidenceHighThreshold))
	require.Equal(t, ConfidenceHigh, ScoreToTier(ConfidenceCertain))
}
