package targetprofile

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/index"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
)

// Registry maps targets to their template selection.
//
// Targets are bound while inputs are read, then Prepare is called with the
// loaded templates before the scan starts. Selections are interned, so targets
// sharing a selector share one memoized decision per template.
type Registry struct {
	templatesDir string

	mu           sync.RWMutex
	targets      map[string]*Selection
	selections   map[string]*Selection
	rules        map[string]*rule
	profiles     map[string]selector
	unrestricted bool

	metadata map[string]*index.Metadata
}

var _ protocols.TargetScope = (*Registry)(nil)

// NewRegistry creates a registry resolving profiles and relative template
// paths against templatesDir.
func NewRegistry(templatesDir string) *Registry {
	return &Registry{
		templatesDir: templatesDir,
		targets:      make(map[string]*Selection),
		selections:   make(map[string]*Selection),
		rules:        make(map[string]*rule),
		profiles:     make(map[string]selector),
	}
}

// ParseLine parses a target line into its target and selection.
func (r *Registry) ParseLine(line string) (string, *Selection, error) {
	target, profile, sel, err := parseLine(line)
	if err != nil {
		return "", nil, err
	}
	if profile != "" {
		base, err := r.profile(profile)
		if err != nil {
			return "", nil, fmt.Errorf("target %q: %w", target, err)
		}
		sel = base.merge(sel)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	compiled, err := r.internRule(sel)
	if err != nil {
		return "", nil, fmt.Errorf("target %q: %w", target, err)
	}
	return target, r.internSelection([]*rule{compiled}), nil
}

// Bind records the selection of a newly stored input; nil means unrestricted.
func (r *Registry) Bind(input string, selection *Selection) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if selection == nil {
		r.unrestricted = true
		if _, ok := r.targets[input]; ok {
			r.targets[input] = nil
		}
		return
	}
	current, ok := r.targets[input]
	switch {
	case !ok:
		r.targets[input] = selection
	case current != nil:
		r.targets[input] = r.union(current, selection)
	}
}

// Merge records the selection of an input that was already stored, so a
// target listed more than once runs the union of its selections and is
// scanned once.
func (r *Registry) Merge(input string, selection *Selection) {
	r.mu.Lock()
	defer r.mu.Unlock()

	current, ok := r.targets[input]
	switch {
	case !ok || current == nil:
		// already unrestricted
	case selection == nil:
		r.targets[input] = nil
	default:
		r.targets[input] = r.union(current, selection)
	}
}

// Scoped reports whether any target has a selection.
func (r *Registry) Scoped() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.selections) > 0
}

// LoadFilter returns the templates worth loading: those selected for at least
// one target. It returns nil when some target is unrestricted, since that
// target needs every template.
func (r *Registry) LoadFilter() index.FilterFunc {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.unrestricted || len(r.rules) == 0 {
		return nil
	}
	rules := make([]*rule, 0, len(r.rules))
	for _, compiled := range r.rules {
		rules = append(rules, compiled)
	}
	return func(m *index.Metadata) bool { return anyMatches(rules, m) }
}

// Prepare indexes the metadata of the templates about to run.
func (r *Registry) Prepare(tpls []*templates.Template) {
	metadata := make(map[string]*index.Metadata, len(tpls))
	for _, tpl := range tpls {
		metadata[tpl.Path] = index.NewMetadataFromTemplate(tpl.Path, tpl)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.metadata = metadata
	for _, selection := range r.selections {
		selection.decisions.Clear()
	}
}

// For returns the selection of input, or nil when every template applies.
func (r *Registry) For(input *contextargs.MetaInput) protocols.TemplateSelection {
	r.mu.RLock()
	selection := r.targets[input.Input]
	r.mu.RUnlock()

	// a nil *Selection must not become a non-nil interface
	if selection == nil {
		return nil
	}
	return selection
}

func (r *Registry) profile(name string) (selector, error) {
	r.mu.RLock()
	sel, ok := r.profiles[name]
	r.mu.RUnlock()
	if ok {
		return sel, nil
	}

	sel, ignored, err := loadProfile(name, r.templatesDir)
	if err != nil {
		return nil, err
	}
	if len(ignored) > 0 {
		gologger.Warning().Msgf("Profile %q keys %s apply to the whole scan and are ignored per target", name, strings.Join(ignored, ", "))
	}

	r.mu.Lock()
	r.profiles[name] = sel
	r.mu.Unlock()
	return sel, nil
}

func (r *Registry) internRule(sel selector) (*rule, error) {
	key, err := canonicalKey(sel)
	if err != nil {
		return nil, err
	}
	if compiled, ok := r.rules[key]; ok {
		return compiled, nil
	}
	compiled, err := compileRule(sel, r.templatesDir)
	if err != nil {
		return nil, err
	}
	r.rules[key] = compiled
	return compiled, nil
}

func (r *Registry) internSelection(rules []*rule) *Selection {
	keys := make([]string, len(rules))
	for i, compiled := range rules {
		keys[i] = compiled.key
	}
	key := strings.Join(keys, "\n")
	if selection, ok := r.selections[key]; ok {
		return selection
	}
	selection := &Selection{registry: r, rules: rules}
	r.selections[key] = selection
	return selection
}

func (r *Registry) union(a, b *Selection) *Selection {
	if a == b {
		return a
	}
	rules := slices.Concat(a.rules, b.rules)
	slices.SortFunc(rules, func(x, y *rule) int { return strings.Compare(x.key, y.key) })
	rules = slices.CompactFunc(rules, func(x, y *rule) bool { return x.key == y.key })
	return r.internSelection(rules)
}

// Selection is the template selection of one or more targets: a template is
// selected when any of its rules selects it.
type Selection struct {
	registry  *Registry
	rules     []*rule
	decisions sync.Map
}

var _ protocols.TemplateSelection = (*Selection)(nil)

// Allows reports whether the template loaded from templatePath is selected.
// Templates unknown to Prepare are allowed rather than silently dropped.
func (s *Selection) Allows(templatePath string) bool {
	if allowed, ok := s.decisions.Load(templatePath); ok {
		return allowed.(bool)
	}

	s.registry.mu.RLock()
	m := s.registry.metadata[templatePath]
	s.registry.mu.RUnlock()

	allowed := m == nil || anyMatches(s.rules, m)
	s.decisions.Store(templatePath, allowed)
	return allowed
}
