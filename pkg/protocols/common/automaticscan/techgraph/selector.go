package techgraph

import "sort"

// Selector resolves detected technology signals into a concrete fire-set of
// template ids using a tech-graph artifact. It is pure and deterministic.
type Selector struct {
	g       *Graph
	byAlias map[string]string // alias/synonym/id/product -> canonical tech id
}

// NewSelector builds a selector with an alias index for fast signal resolution.
func NewSelector(g *Graph) *Selector {
	s := &Selector{g: g, byAlias: make(map[string]string)}
	// synonyms first (authoritative), then ids/products/aliases without clobbering.
	for a, id := range g.Synonyms {
		s.byAlias[normToken(a)] = id
	}
	for id, t := range g.Techs {
		if _, ok := s.byAlias[normToken(id)]; !ok {
			s.byAlias[normToken(id)] = id
		}
		if t.Product != "" {
			if _, ok := s.byAlias[normToken(t.Product)]; !ok {
				s.byAlias[normToken(t.Product)] = id
			}
		}
		for _, a := range t.Aliases {
			if _, ok := s.byAlias[normToken(a)]; !ok {
				s.byAlias[normToken(a)] = id
			}
		}
	}
	return s
}

// Resolve maps detected signal tokens (wappalyzer names, detection tags, cpe
// products) to canonical tech ids. Tokens that match no node are returned as
// unresolved so the caller can apply tag-overlap fallback.
func (s *Selector) Resolve(signals []string) (techIDs, unresolved []string) {
	seenTech := map[string]struct{}{}
	seenUnres := map[string]struct{}{}
	for _, sig := range signals {
		tok := normToken(sig)
		if tok == "" || genericTokens[tok] {
			continue
		}
		if id, ok := s.byAlias[tok]; ok {
			if _, dup := seenTech[id]; !dup {
				seenTech[id] = struct{}{}
				techIDs = append(techIDs, id)
			}
			continue
		}
		if _, dup := seenUnres[tok]; !dup {
			seenUnres[tok] = struct{}{}
			unresolved = append(unresolved, tok)
		}
	}
	sort.Strings(techIDs)
	sort.Strings(unresolved)
	return techIDs, unresolved
}

// FireSet returns the precise template ids to execute for the given techs at the
// requested coverage tier (dependents + tier-gated baseline).
func (s *Selector) FireSet(tier Tier, techIDs []string) []string {
	ids := map[string]struct{}{}
	for _, id := range techIDs {
		if t, ok := s.g.Techs[id]; ok {
			for _, r := range t.Templates {
				ids[r.ID] = struct{}{}
			}
		}
	}
	for _, b := range s.g.Baseline {
		if tierIncludesBaseline(tier, b.Tier) {
			ids[b.ID] = struct{}{}
		}
	}
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// BaselineIDs returns just the tier-gated baseline ids.
func (s *Selector) BaselineIDs(tier Tier) []string {
	var out []string
	for _, b := range s.g.Baseline {
		if tierIncludesBaseline(tier, b.Tier) {
			out = append(out, b.ID)
		}
	}
	sort.Strings(out)
	return out
}

// tierIncludesBaseline gates baseline membership by coverage tier:
//   - lean: no baseline (dependents only)
//   - balanced: balanced baseline only
//   - thorough: balanced + thorough baseline
func tierIncludesBaseline(scan, entry Tier) bool {
	switch scan {
	case TierLean:
		return false
	case TierThorough:
		return true
	default: // balanced
		return entry == TierBalanced
	}
}

// NormalizeTier coerces arbitrary input to a valid tier, defaulting to balanced.
func NormalizeTier(s string) Tier {
	switch Tier(s) {
	case TierLean:
		return TierLean
	case TierThorough:
		return TierThorough
	default:
		return TierBalanced
	}
}
