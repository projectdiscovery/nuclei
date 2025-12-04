package index

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
)

// Filter represents filtering criteria for template metadata.
//
// Inclusion fields (e.g., Authors, Tags, IDs, Severities, ProtocolTypes) use
// AND logic across different filter types and OR logic within each type.
// Exclusion fields (e.g., ExcludeTags, ExcludeIDs, ExcludeSeverities,
// ExcludeProtocolTypes) take precedence over inclusion fields. Additionally,
// IncludeTemplates and IncludeTags can force inclusion of templates even if
// they match exclusion criteria.
type Filter struct {
	// Authors to include.
	Authors []string

	// Tags to include.
	Tags []string

	// ExcludeTags to exclude (takes precedence over Tags).
	ExcludeTags []string

	// IncludeTags to force include even if excluded.
	IncludeTags []string

	// IDs to include (supports wildcards, OR logic).
	IDs []string

	// ExcludeIDs to exclude (supports wildcards).
	ExcludeIDs []string

	// IncludeTemplates paths to force include even if excluded.
	IncludeTemplates []string

	// ExcludeTemplates paths to exclude.
	ExcludeTemplates []string

	// Severities to include.
	Severities []severity.Severity

	// ExcludeSeverities to exclude.
	ExcludeSeverities []severity.Severity

	// ProtocolTypes to include.
	ProtocolTypes []types.ProtocolType

	// ExcludeProtocolTypes to exclude.
	ExcludeProtocolTypes []types.ProtocolType
}

// Matches checks if metadata matches the filter criteria.
func (f *Filter) Matches(m *Metadata) bool {
	if f.isForcedInclude(m) {
		return true
	}

	if f.isExcluded(m) {
		return false
	}

	if !f.matchesIncludes(m) {
		return false
	}

	return true
}

// isForcedInclude checks if template is forced to be included.
func (f *Filter) isForcedInclude(m *Metadata) bool {
	if len(f.IncludeTemplates) > 0 {
		for _, includePath := range f.IncludeTemplates {
			if matchesPath(m.FilePath, includePath) {
				return true
			}
		}
	}

	if len(f.IncludeTags) > 0 {
		if slices.ContainsFunc(f.IncludeTags, m.HasTag) {
			return true
		}
	}

	return false
}

// isExcluded checks if template should be excluded.
func (f *Filter) isExcluded(m *Metadata) bool {
	if len(f.ExcludeTemplates) > 0 {
		for _, excludePath := range f.ExcludeTemplates {
			if matchesPath(m.FilePath, excludePath) {
				return true
			}
		}
	}

	if len(f.ExcludeTags) > 0 {
		if slices.ContainsFunc(f.ExcludeTags, m.HasTag) {
			return true
		}
	}

	if len(f.ExcludeIDs) > 0 {
		for _, excludeID := range f.ExcludeIDs {
			if matchesID(m.ID, excludeID) {
				return true
			}
		}
	}

	if len(f.ExcludeSeverities) > 0 {
		if slices.ContainsFunc(f.ExcludeSeverities, m.MatchesSeverity) {
			return true
		}
	}

	if len(f.ExcludeProtocolTypes) > 0 {
		if slices.ContainsFunc(f.ExcludeProtocolTypes, m.MatchesProtocol) {
			return true
		}
	}

	return false
}

// matchesIncludes checks if metadata matches include filters.
//
// Returns true if no include filters are specified, or if all specified filter
// types match.
func (f *Filter) matchesIncludes(m *Metadata) bool {
	if len(f.Authors) > 0 {
		if !slices.ContainsFunc(f.Authors, m.HasAuthor) {
			return false
		}
	}

	if len(f.Tags) > 0 {
		if !slices.ContainsFunc(f.Tags, m.HasTag) {
			return false
		}
	}

	if len(f.IDs) > 0 {
		matched := false
		for _, id := range f.IDs {
			if matchesID(m.ID, id) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(f.Severities) > 0 {
		if !slices.ContainsFunc(f.Severities, m.MatchesSeverity) {
			return false
		}
	}

	if len(f.ProtocolTypes) > 0 {
		if !slices.ContainsFunc(f.ProtocolTypes, m.MatchesProtocol) {
			return false
		}
	}

	return true
}

// matchesID checks if template ID matches pattern (supports wildcards).
func matchesID(templateID, pattern string) bool {
	// Convert to lowercase for case-insensitive matching
	templateID = strings.ToLower(templateID)
	pattern = strings.ToLower(pattern)

	if templateID == pattern {
		return true
	}

	matched, _ := filepath.Match(pattern, templateID)

	return matched
}

// matchesPath checks if template path matches pattern.
func matchesPath(templatePath, pattern string) bool {
	templatePath = filepath.Clean(templatePath)
	pattern = filepath.Clean(pattern)

	if templatePath == pattern {
		return true
	}

	if strings.HasPrefix(templatePath, pattern+string(filepath.Separator)) {
		return true
	}

	matched, _ := filepath.Match(pattern, templatePath)

	return matched
}

// FilterFunc is a function that filters metadata.
type FilterFunc func(*Metadata) bool

// UnmarshalFilter creates a Filter from nuclei options.
func UnmarshalFilter(
	authors, tags, excludeTags, includeTags []string,
	ids, excludeIDs []string,
	includeTemplates, excludeTemplates []string,
	severities, excludeSeverities []string,
	protocolTypes, excludeProtocolTypes []string,
) (*Filter, error) {
	filter := &Filter{
		Authors:          authors,
		Tags:             tags,
		ExcludeTags:      excludeTags,
		IncludeTags:      includeTags,
		IDs:              ids,
		ExcludeIDs:       excludeIDs,
		IncludeTemplates: includeTemplates,
		ExcludeTemplates: excludeTemplates,
	}

	for _, sev := range severities {
		holder := &severity.Holder{}
		if err := holder.UnmarshalYAML(func(v interface{}) error {
			*v.(*string) = sev
			return nil
		}); err == nil {
			filter.Severities = append(filter.Severities, holder.Severity)
		}
	}

	for _, sev := range excludeSeverities {
		holder := &severity.Holder{}
		if err := holder.UnmarshalYAML(func(v interface{}) error {
			*v.(*string) = sev
			return nil
		}); err == nil {
			filter.ExcludeSeverities = append(filter.ExcludeSeverities, holder.Severity)
		}
	}

	for _, pt := range protocolTypes {
		holder := &types.TypeHolder{}
		if err := holder.UnmarshalYAML(func(v interface{}) error {
			*v.(*string) = pt
			return nil
		}); err == nil && holder.ProtocolType != types.InvalidProtocol {
			filter.ProtocolTypes = append(filter.ProtocolTypes, holder.ProtocolType)
		}
	}

	for _, pt := range excludeProtocolTypes {
		holder := &types.TypeHolder{}
		if err := holder.UnmarshalYAML(func(v interface{}) error {
			*v.(*string) = pt
			return nil
		}); err == nil && holder.ProtocolType != types.InvalidProtocol {
			filter.ExcludeProtocolTypes = append(filter.ExcludeProtocolTypes, holder.ProtocolType)
		}
	}

	return filter, nil
}

// UnmarshalFilterFunc creates a FilterFunc from filter criteria.
func UnmarshalFilterFunc(filter *Filter) FilterFunc {
	if filter == nil {
		return func(*Metadata) bool { return true }
	}

	return filter.Matches
}

// IsEmpty returns true if filter has no criteria set.
func (f *Filter) IsEmpty() bool {
	return len(f.Authors) == 0 &&
		len(f.Tags) == 0 &&
		len(f.ExcludeTags) == 0 &&
		len(f.IncludeTags) == 0 &&
		len(f.IDs) == 0 &&
		len(f.ExcludeIDs) == 0 &&
		len(f.IncludeTemplates) == 0 &&
		len(f.ExcludeTemplates) == 0 &&
		len(f.Severities) == 0 &&
		len(f.ExcludeSeverities) == 0 &&
		len(f.ProtocolTypes) == 0 &&
		len(f.ExcludeProtocolTypes) == 0
}

// String returns a human-readable representation of the filter.
func (f *Filter) String() string {
	var parts []string

	if len(f.Authors) > 0 {
		parts = append(parts, "authors="+strings.Join(f.Authors, ","))
	}

	if len(f.Tags) > 0 {
		parts = append(parts, "tags="+strings.Join(f.Tags, ","))
	}

	if len(f.ExcludeTags) > 0 {
		parts = append(parts, "exclude-tags="+strings.Join(f.ExcludeTags, ","))
	}

	if len(f.IDs) > 0 {
		parts = append(parts, "ids="+strings.Join(f.IDs, ","))
	}

	if len(f.Severities) > 0 {
		sevs := make([]string, len(f.Severities))
		for i, s := range f.Severities {
			sevs[i] = s.String()
		}

		parts = append(parts, "severities="+strings.Join(sevs, ","))
	}

	if len(f.ProtocolTypes) > 0 {
		pts := make([]string, len(f.ProtocolTypes))
		for i, p := range f.ProtocolTypes {
			pts[i] = p.String()
		}

		parts = append(parts, "types="+strings.Join(pts, ","))
	}

	if len(parts) == 0 {
		return "filter=<nil>"
	}

	return "filter(" + strings.Join(parts, ", ") + ")"
}
