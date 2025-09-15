package generators

import "testing"

func TestAttackTypeHelpers(t *testing.T) {
	// GetSupportedAttackTypes should include three values
	types := GetSupportedAttackTypes()
	if len(types) != 3 {
		t.Fatalf("expected 3 types, got %d", len(types))
	}
	// toAttackType valid
	if got, err := toAttackType("pitchfork"); err != nil || got != PitchForkAttack {
		t.Fatalf("toAttackType failed: %v %v", got, err)
	}
	// toAttackType invalid
	if _, err := toAttackType("nope"); err == nil {
		t.Fatalf("expected error for invalid attack type")
	}
	// normalizeValue and String
	if normalizeValue("  ClusterBomb  ") != "clusterbomb" {
		t.Fatalf("normalizeValue failed")
	}
	if ClusterBombAttack.String() != "clusterbomb" {
		t.Fatalf("String failed")
	}
}
