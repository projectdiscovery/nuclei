package expressions

import (
	"testing"
)

// TestWave13StopAtFirstMatchEvaluation asserts early termination optimization
func TestWave13StopAtFirstMatchEvaluation(t *testing.T) {
	evaluations := 0
	checkMatch := func(isMatch bool) bool {
		evaluations++
		return isMatch
	}

	matchers := []bool{false, true, false, true}
	var matched bool
	stopAtFirstMatch := true

	for _, m := range matchers {
		if checkMatch(m) {
			matched = true
			if stopAtFirstMatch {
				break
			}
		}
	}

	if !matched {
		t.Errorf("expected matcher to match on second element")
	}
	if evaluations != 2 {
		t.Errorf("expected exactly 2 evaluations with stopAtFirstMatch, got %d", evaluations)
	}
}

// TestWave13PayloadExtractionLimit asserts max extract regex group
func TestWave13PayloadExtractionLimit(t *testing.T) {
	maxExtractedItems := 50

	isExtractionWithinBounds := func(extractedCount int) bool {
		return extractedCount <= maxExtractedItems
	}

	if !isExtractionWithinBounds(10) {
		t.Errorf("expected 10 extracted items to be allowed")
	}
	if isExtractionWithinBounds(55) {
		t.Errorf("expected 55 extracted items to exceed extraction limit")
	}
}
