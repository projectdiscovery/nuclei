package techgraph

import (
	"reflect"
	"testing"
)

func testGraph() *Graph {
	return &Graph{
		Techs: map[string]*Tech{
			"wordpress": {ID: "wordpress", Product: "wordpress", Aliases: []string{"wordpress"},
				Templates: []TemplateRef{{ID: "wp-cve-1"}, {ID: "wp-plugin-1", Source: "platform"}}},
			"atlassian:confluence": {ID: "atlassian:confluence", Product: "confluence", Aliases: []string{"confluence"},
				Templates: []TemplateRef{{ID: "confluence-cve-1"}}},
		},
		Baseline: []BaselineEntry{
			{ID: "git-config", Tier: TierBalanced},
			{ID: "noisy-osinty", Tier: TierThorough},
		},
		Synonyms: map[string]string{"aem": "adobe:experience_manager"},
	}
}

func TestResolve(t *testing.T) {
	s := NewSelector(testGraph())
	tech, unres := s.Resolve([]string{"WordPress", "confluence", "php", "cve"})
	if len(tech) != 2 {
		t.Fatalf("want 2 techs, got %v", tech)
	}
	if len(unres) != 1 || unres[0] != "php" {
		t.Fatalf("want [php] unresolved, got %v", unres)
	}
}

func TestFireSetTiers(t *testing.T) {
	s := NewSelector(testGraph())
	techs := []string{"wordpress"}

	lean := s.FireSet(TierLean, techs)
	if want := []string{"wp-cve-1", "wp-plugin-1"}; !reflect.DeepEqual(lean, want) {
		t.Fatalf("lean: want %v, got %v", want, lean)
	}
	bal := s.FireSet(TierBalanced, techs)
	if want := []string{"git-config", "wp-cve-1", "wp-plugin-1"}; !reflect.DeepEqual(bal, want) {
		t.Fatalf("balanced: want %v, got %v", want, bal)
	}
	tho := s.FireSet(TierThorough, techs)
	if want := []string{"git-config", "noisy-osinty", "wp-cve-1", "wp-plugin-1"}; !reflect.DeepEqual(tho, want) {
		t.Fatalf("thorough: want %v, got %v", want, tho)
	}
}

func TestNormalizeTier(t *testing.T) {
	for in, want := range map[string]Tier{"lean": TierLean, " THOROUGH ": TierThorough, "": TierBalanced, "x": TierBalanced} {
		if got := NormalizeTier(in); got != want {
			t.Fatalf("NormalizeTier(%q)=%q want %q", in, got, want)
		}
	}
}

func TestParseTier(t *testing.T) {
	if _, err := ParseTier("not-a-tier"); err == nil {
		t.Fatal("expected error for unknown tier")
	}
	got, err := ParseTier(" Lean ")
	if err != nil || got != TierLean {
		t.Fatalf("ParseTier(Lean)=%q %v", got, err)
	}
}

func TestAbsentDependents(t *testing.T) {
	s := NewSelector(testGraph())
	candidates := []Candidate{
		{ID: "new-wp", Tags: []string{"wordpress"}, Category: "cves"},
		{ID: "ambiguous", Tags: []string{"wordpress", "confluence"}, Category: "cves"},
		{ID: "fuzzed", Tags: []string{"wordpress"}, Category: "fuzzing"},
		{ID: "wp-cve-1", Tags: []string{"wordpress"}, Category: "cves"},
		{ID: "short", Tags: []string{"wp"}, Category: "cves"},
		{ID: "other-tech", Tags: []string{"wordpress"}, Category: "cves"},
	}
	got := s.AbsentDependents([]string{"wordpress"}, candidates[:5])
	if want := []string{"new-wp"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	if got := s.AbsentDependents([]string{"atlassian:confluence"}, candidates[5:]); len(got) != 0 {
		t.Fatalf("wordpress tag must not attach to confluence, got %v", got)
	}
	if got := s.AbsentDependents([]string{"wordpress"}, []Candidate{{ID: "no-path", Tags: []string{"wordpress"}}}); len(got) != 0 {
		t.Fatalf("unknown category must not be added, got %v", got)
	}
}
