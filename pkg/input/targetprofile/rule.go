package targetprofile

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/index"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

// rule is a compiled selector.
type rule struct {
	key    string
	filter *index.Filter
	paths  []string
	tech   map[string]struct{}
}

func compileRule(sel selector, templatesDir string) (*rule, error) {
	var severities, excludeSeverities severity.Severities
	if err := setAll(&severities, sel[keySeverity]); err != nil {
		return nil, fmt.Errorf("key %q: %w", keySeverity, err)
	}
	if err := setAll(&excludeSeverities, sel[keyExcludeSeverity]); err != nil {
		return nil, fmt.Errorf("key %q: %w", keyExcludeSeverity, err)
	}
	var protocols, excludeProtocols types.ProtocolTypes
	if err := setAll(&protocols, sel[keyType]); err != nil {
		return nil, fmt.Errorf("key %q: %w", keyType, err)
	}
	if err := setAll(&excludeProtocols, sel[keyExcludeType]); err != nil {
		return nil, fmt.Errorf("key %q: %w", keyExcludeType, err)
	}

	r := &rule{
		filter: &index.Filter{
			Authors:              lowered(sel[keyAuthor]),
			Tags:                 lowered(sel[keyTags]),
			ExcludeTags:          lowered(sel[keyExcludeTags]),
			IncludeTags:          lowered(sel[keyIncludeTags]),
			IDs:                  sel[keyTemplateID],
			ExcludeIDs:           sel[keyExcludeID],
			Severities:           severities,
			ExcludeSeverities:    excludeSeverities,
			ProtocolTypes:        protocols,
			ExcludeProtocolTypes: excludeProtocols,
		},
	}
	for _, path := range sel[keyTemplates] {
		if !filepath.IsAbs(path) {
			path = filepath.Join(templatesDir, path)
		}
		r.paths = append(r.paths, filepath.Clean(path))
	}
	if len(sel[keyTech]) > 0 {
		r.tech = make(map[string]struct{}, len(sel[keyTech]))
		for _, tech := range sel[keyTech] {
			for _, token := range techTokens(tech) {
				r.tech[token] = struct{}{}
			}
		}
	}

	key, err := canonicalKey(sel)
	if err != nil {
		return nil, err
	}
	r.key = key
	return r, nil
}

// matches reports whether the template described by m is selected.
func (r *rule) matches(m *index.Metadata) bool {
	if !r.filter.Matches(m) {
		return false
	}
	if len(r.paths) > 0 && !slices.ContainsFunc(r.paths, func(path string) bool { return underPath(m.FilePath, path) }) {
		return false
	}
	return r.matchesTech(m)
}

// matchesTech implements tech-aware selection: templates bound to a product run
// only when the target runs that product, every other template always runs.
// A template is bound when it declares metadata.product; its tags are matched
// too because product metadata is sometimes imprecise (CVE-2020-1938 targets
// Tomcat but declares product "geode"). Erring on running a template keeps
// coverage when metadata and the target's tech list disagree.
func (r *rule) matchesTech(m *index.Metadata) bool {
	if len(r.tech) == 0 || m.Product == "" {
		return true
	}
	if _, ok := r.tech[normalizeTech(m.Product)]; ok {
		return true
	}
	for _, tag := range m.Tags {
		if _, ok := r.tech[normalizeTech(tag)]; ok {
			return true
		}
	}
	return false
}

func anyMatches(rules []*rule, m *index.Metadata) bool {
	return slices.ContainsFunc(rules, func(r *rule) bool { return r.matches(m) })
}

// techTokens expands a tech name reported by a fingerprinting tool into the
// tokens template metadata uses: "Apache Tomcat" and "apache:tomcat" yield
// apache-tomcat, apache and tomcat. Extra tokens can only select more
// templates, never fewer.
func techTokens(tech string) []string {
	words := strings.FieldsFunc(strings.ToLower(tech), func(r rune) bool { return r == ':' || unicode.IsSpace(r) })
	if len(words) == 0 {
		return nil
	}
	tokens := []string{normalizeTech(strings.Join(words, " "))}
	if len(words) > 1 {
		for _, word := range words {
			tokens = append(tokens, normalizeTech(word))
		}
	}
	return tokens
}

// normalizeTech maps a product or tag to its token form ("Apache_Tomcat" and
// "apache tomcat" both become apache-tomcat).
func normalizeTech(tech string) string {
	tech = strings.ReplaceAll(strings.ToLower(tech), "_", "-")
	return strings.Join(strings.Fields(tech), "-")
}

func underPath(templatePath, path string) bool {
	templatePath = filepath.Clean(templatePath)
	if templatePath == path || strings.HasPrefix(templatePath, path+string(filepath.Separator)) {
		return true
	}
	matched, _ := filepath.Match(path, templatePath)
	return matched
}

// canonicalKey identifies equivalent selectors so they share one compiled rule.
func canonicalKey(sel selector) (string, error) {
	normalized := make(map[string][]string, len(sel))
	for key, values := range sel {
		values = slices.Clone(values)
		slices.Sort(values)
		normalized[key] = slices.Compact(values)
	}
	data, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func setAll(value interface{ Set(string) error }, values []string) error {
	if len(values) == 0 {
		return nil
	}
	return value.Set(strings.Join(values, ","))
}

func lowered(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = strings.ToLower(value)
	}
	return out
}
