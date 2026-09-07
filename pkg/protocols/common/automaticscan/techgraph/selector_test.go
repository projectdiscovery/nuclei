package techgraph

import "testing"

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
	if len(lean) != 2 { // dependents only, no baseline
		t.Fatalf("lean: want 2, got %v", lean)
	}
	bal := s.FireSet(TierBalanced, techs)
	if len(bal) != 3 { // + balanced baseline (git-config)
		t.Fatalf("balanced: want 3, got %v", bal)
	}
	tho := s.FireSet(TierThorough, techs)
	if len(tho) != 4 { // + thorough baseline
		t.Fatalf("thorough: want 4, got %v", tho)
	}
}

func TestNormalizeTier(t *testing.T) {
	for in, want := range map[string]Tier{"lean": TierLean, "thorough": TierThorough, "": TierBalanced, "x": TierBalanced} {
		if got := NormalizeTier(in); got != want {
			t.Fatalf("NormalizeTier(%q)=%q want %q", in, got, want)
		}
	}
}
