package contextargs

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

// TargetFilter contains optional template selection overrides attached to a
// single input target. The Has* fields distinguish an omitted JSONL field
// (inherit the corresponding global option) from an explicitly provided field.
type TargetFilter struct {
	Tags        []string            `json:"tags,omitempty"`
	ExcludeTags []string            `json:"exclude-tags,omitempty"`
	Severities  severity.Severities `json:"severity,omitempty"`
	Templates   []string            `json:"templates,omitempty"`

	HasTags        bool `json:"-"`
	HasExcludeTags bool `json:"-"`
	HasSeverities  bool `json:"-"`
	HasTemplates   bool `json:"-"`
	SourceLine     int  `json:"-"`

	prepared *preparedTargetFilter
}

// preparedTargetFilter is immutable after construction. MetaInput clones can
// therefore share it without copying potentially large, expanded template
// path sets for every template/target pair.
type preparedTargetFilter struct {
	effectiveTags        map[string]struct{}
	effectiveExcludeTags map[string]struct{}
	effectiveSeverities  map[severity.Severity]struct{}
	effectiveTemplates   []string
	effectiveIncludes    []string
	restrictTemplates    bool
	identity             string
}

// Prepare resolves inheritance and compiles the effective criteria used during
// execution. Callers must finish preparing filters before a scan starts.
func (f *TargetFilter) Prepare(tags, excludeTags []string, severities severity.Severities, templatePaths, includeTemplatePaths []string, restrictTemplates bool) {
	if f == nil {
		return
	}

	prepared := &preparedTargetFilter{
		effectiveTags:        stringSet(tags),
		effectiveExcludeTags: stringSet(excludeTags),
		effectiveSeverities:  make(map[severity.Severity]struct{}, len(severities)),
		effectiveTemplates:   sortedCleanPaths(templatePaths),
		effectiveIncludes:    sortedCleanPaths(includeTemplatePaths),
		restrictTemplates:    restrictTemplates,
	}
	for _, value := range severities {
		prepared.effectiveSeverities[value] = struct{}{}
	}
	prepared.identity = f.buildIdentity()
	f.prepared = prepared
}

// MatchesTemplate reports whether a template is enabled for this target.
// Workflows bypass this matcher to preserve existing workflow semantics. The
// runner rejects workflows when any JSONL target override is present because
// workflow child templates cannot yet apply independent target filters.
func (f *TargetFilter) MatchesTemplate(templatePath string, templateTags []string, templateSeverity severity.Severity, isWorkflow bool) bool {
	if f == nil || f.prepared == nil {
		return true
	}
	if isWorkflow {
		return true
	}

	templatePath = filepath.Clean(templatePath)
	if containsSortedPath(f.prepared.effectiveIncludes, templatePath) {
		return true
	}

	if f.prepared.restrictTemplates {
		if !containsSortedPath(f.prepared.effectiveTemplates, templatePath) {
			return false
		}
	}

	if len(f.prepared.effectiveTags) > 0 {
		matched := false
		for _, tag := range templateTags {
			if _, ok := f.prepared.effectiveTags[strings.ToLower(tag)]; ok {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	for _, tag := range templateTags {
		if _, excluded := f.prepared.effectiveExcludeTags[strings.ToLower(tag)]; excluded {
			return false
		}
	}

	if len(f.prepared.effectiveSeverities) > 0 {
		if _, ok := f.prepared.effectiveSeverities[templateSeverity]; !ok {
			return false
		}
	}
	return true
}

func (f *TargetFilter) clone() *TargetFilter {
	if f == nil {
		return nil
	}
	cloned := &TargetFilter{
		Tags:           append([]string(nil), f.Tags...),
		ExcludeTags:    append([]string(nil), f.ExcludeTags...),
		Severities:     append(severity.Severities(nil), f.Severities...),
		Templates:      append([]string(nil), f.Templates...),
		HasTags:        f.HasTags,
		HasExcludeTags: f.HasExcludeTags,
		HasSeverities:  f.HasSeverities,
		HasTemplates:   f.HasTemplates,
		SourceLine:     f.SourceLine,
		prepared:       f.prepared,
	}
	return cloned
}

func (f *TargetFilter) identity() string {
	if f == nil {
		return ""
	}
	if f.prepared != nil {
		return f.prepared.identity
	}
	return f.buildIdentity()
}

func (f *TargetFilter) buildIdentity() string {
	type canonicalIdentity struct {
		Tags           []string
		ExcludeTags    []string
		Severities     []string
		Templates      []string
		HasTags        bool
		HasExcludeTags bool
		HasSeverities  bool
		HasTemplates   bool
	}
	identity := canonicalIdentity{
		Tags:           sortedStrings(f.Tags),
		ExcludeTags:    sortedStrings(f.ExcludeTags),
		Severities:     sortedSeverities(f.Severities),
		Templates:      sortedStrings(f.Templates),
		HasTags:        f.HasTags,
		HasExcludeTags: f.HasExcludeTags,
		HasSeverities:  f.HasSeverities,
		HasTemplates:   f.HasTemplates,
	}
	data, err := json.Marshal(identity)
	if err != nil {
		return ""
	}
	return string(data)
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func sortedSeverities(values severity.Severities) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.String())
	}
	sort.Strings(result)
	return result
}

// sortedCleanPaths normalizes a defensive copy so containsSortedPath can
// binary-search regardless of caller ordering or path form.
func sortedCleanPaths(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	result := make([]string, 0, len(paths))
	for _, path := range paths {
		result = append(result, filepath.Clean(path))
	}
	sort.Strings(result)
	return result
}

func containsSortedPath(paths []string, path string) bool {
	index := sort.SearchStrings(paths, path)
	return index < len(paths) && paths[index] == path
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[strings.ToLower(value)] = struct{}{}
	}
	return result
}
