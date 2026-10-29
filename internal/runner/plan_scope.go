package runner

import (
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
)

// planScope narrows the templates run on each target by the scan plan filters
// (strict-probe reachability, tech filter), on top of the per-target profiles
// in base. It is a protocols.TargetScope, so the engine skips, counts and
// narrows clusters for these pairs the same way it does for profiles.
type planScope struct {
	base  protocols.TargetScope
	allow func(*templates.Template, *contextargs.MetaInput) bool
	// byPath maps a template path to its template. A path shared by several
	// templates, or empty, is left out, so such templates are never filtered.
	byPath map[string]*templates.Template

	mu         sync.RWMutex
	selections map[planKey]*planSelection
}

// planKey identifies one selection: the target and the profile selection it
// narrows. Profile selections are comparable by contract.
type planKey struct {
	input string
	ip    string
	base  protocols.TemplateSelection
}

// planSelection is the selection of one target.
type planSelection struct {
	base  protocols.TemplateSelection
	scope *planScope
	input *contextargs.MetaInput
}

var _ protocols.TargetScope = (*planScope)(nil)

func newPlanScope(base protocols.TargetScope, allow func(*templates.Template, *contextargs.MetaInput) bool, tpls []*templates.Template) *planScope {
	byPath := make(map[string]*templates.Template, len(tpls))
	shared := make(map[string]struct{})
	for _, t := range tpls {
		if t == nil || t.Path == "" {
			continue
		}
		if _, ok := byPath[t.Path]; ok {
			shared[t.Path] = struct{}{}
			continue
		}
		byPath[t.Path] = t
	}
	for path := range shared {
		delete(byPath, path)
	}
	return &planScope{
		base:       base,
		allow:      allow,
		byPath:     byPath,
		selections: make(map[planKey]*planSelection),
	}
}

// For returns the selection for input. It is the same value for the same
// input, so the engine can group targets by selection.
func (s *planScope) For(input *contextargs.MetaInput) protocols.TemplateSelection {
	var base protocols.TemplateSelection
	if s.base != nil {
		base = s.base.For(input)
	}
	if input == nil {
		return base
	}
	key := planKey{input: input.Input, ip: input.CustomIP, base: base}
	s.mu.RLock()
	sel, ok := s.selections[key]
	s.mu.RUnlock()
	if ok {
		return sel
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if sel, ok := s.selections[key]; ok {
		return sel
	}
	sel = &planSelection{base: base, scope: s, input: input.Clone()}
	s.selections[key] = sel
	return sel
}

// Allows reports whether the profiles and the plan filters select the template.
func (p *planSelection) Allows(templatePath string) bool {
	if p.base != nil && !p.base.Allows(templatePath) {
		return false
	}
	t, ok := p.scope.byPath[templatePath]
	if !ok {
		return true
	}
	return p.scope.allow(t, p.input)
}
