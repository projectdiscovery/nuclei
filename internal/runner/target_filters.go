package runner

import (
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
)

// prepareTargetFilters resolves JSONL inheritance before template loading. The
// loader is widened to the union of all per-target selections, while each
// MetaInput keeps an effective filter that narrows execution back to that
// target's criteria.
func (r *Runner) prepareTargetFilters(loaderConfig *loader.Config) error {
	targetProvider, ok := r.inputProvider.(provider.PerTargetInputProvider)
	if !ok || r.inputProvider.InputType() != provider.TargetInputProvider {
		return nil
	}

	inputs := targetProvider.TargetInputs()
	if len(inputs) == 0 {
		return fmt.Errorf("jsonl target input did not contain any targets")
	}

	hasOverrides := false
	hasTemplateOverrides := false
	for _, input := range inputs {
		filter := input.TargetFilter
		if filter == nil {
			return fmt.Errorf("jsonl target %q is missing filter metadata", input.Input)
		}
		if filter.HasTags || filter.HasExcludeTags || filter.HasSeverities || filter.HasTemplates {
			hasOverrides = true
		}
		if filter.HasTemplates {
			hasTemplateOverrides = true
		}
	}
	if !hasOverrides {
		// With no per-target overrides, leave the loader's normal CLI behavior
		// untouched and remove empty metadata so IDs/hashes remain compatible.
		for _, input := range inputs {
			input.TargetFilter = nil
		}
		return nil
	}
	if r.options.AutomaticScan {
		return fmt.Errorf("automatic scan is not supported with per-target JSONL overrides")
	}
	if len(r.options.Workflows) > 0 || len(r.options.WorkflowURLs) > 0 {
		return fmt.Errorf("workflows are not supported with per-target JSONL overrides")
	}
	if r.options.EnableGlobalMatchersTemplates {
		return fmt.Errorf("global matchers are not supported with per-target JSONL overrides")
	}
	if hasTemplateOverrides && len(r.options.TemplateURLs) > 0 {
		return fmt.Errorf("global remote template URLs are not supported together with per-target template overrides")
	}

	// Per-target tag/severity combinations cannot be represented by the
	// loader's global AND filter. Load a safe superset, while retaining the
	// built-in ignore list and all unrelated global filters.
	loaderConfig.Tags = nil
	loaderConfig.Severities = nil
	loaderConfig.ExcludeTags = append([]string(nil), config.ReadIgnoreFile().Tags...)

	var (
		unionTemplatePaths   = make(map[string]struct{})
		loadDefaultTemplates bool
	)

	var globalTemplatePaths []string
	if hasTemplateOverrides && len(r.options.Templates) > 0 {
		resolved, err := resolveTargetTemplatePaths(r.catalog, r.options.Templates, 0, false)
		if err != nil {
			return fmt.Errorf("could not resolve global templates for JSONL target inheritance: %w", err)
		}
		globalTemplatePaths = resolved
		for _, path := range resolved {
			unionTemplatePaths[path] = struct{}{}
		}
	}

	var globalIncludeTemplatePaths []string
	if len(r.options.IncludeTemplates) > 0 {
		resolved, err := resolveTargetTemplatePaths(r.catalog, r.options.IncludeTemplates, 0, false)
		if err != nil {
			return fmt.Errorf("could not resolve globally included templates for JSONL target inheritance: %w", err)
		}
		globalIncludeTemplatePaths = resolved
	}

	var defaultTemplatePaths []string
	if hasTemplateOverrides {
		for _, input := range inputs {
			filter := input.TargetFilter
			if (filter.HasTemplates && len(filter.Templates) == 0) ||
				(!filter.HasTemplates && len(r.options.Templates) == 0) {
				loadDefaultTemplates = true
				break
			}
		}
		if loadDefaultTemplates {
			resolved, err := resolveTargetTemplatePaths(r.catalog, []string{config.DefaultConfig.TemplatesDirectory}, 0, false)
			if err != nil {
				return fmt.Errorf("could not resolve default templates for JSONL target inheritance: %w", err)
			}
			defaultTemplatePaths = resolved
		}
	}

	resolvedTemplateOverrides := make(map[string][]string)
	for _, input := range inputs {
		filter := input.TargetFilter

		effectiveTags := []string(r.options.Tags)
		if filter.HasTags {
			effectiveTags = filter.Tags
		}

		effectiveExcludeTags := []string(r.options.ExcludeTags)
		if filter.HasExcludeTags {
			effectiveExcludeTags = filter.ExcludeTags
		}
		effectiveExcludeTags = removeIncludedTags(effectiveExcludeTags, []string(r.options.IncludeTags))

		effectiveSeverities := append(severity.Severities(nil), r.options.Severities...)
		if filter.HasSeverities {
			effectiveSeverities = append(severity.Severities(nil), filter.Severities...)
		}

		var (
			effectiveTemplatePaths []string
			restrictTemplates      bool
		)
		if hasTemplateOverrides {
			switch {
			case filter.HasTemplates && len(filter.Templates) == 0:
				// An explicitly empty -templates equivalent clears the global
				// selection and falls back to the default template catalog.
				effectiveTemplatePaths = defaultTemplatePaths
				restrictTemplates = true
			case filter.HasTemplates:
				cacheKey := canonicalTargetSelectors(filter.Templates)
				resolved, ok := resolvedTemplateOverrides[cacheKey]
				if !ok {
					var err error
					resolved, err = resolveTargetTemplatePaths(r.catalog, filter.Templates, filter.SourceLine, true)
					if err != nil {
						return err
					}
					resolvedTemplateOverrides[cacheKey] = resolved
				}
				effectiveTemplatePaths = resolved
				restrictTemplates = true
				for _, path := range resolved {
					unionTemplatePaths[path] = struct{}{}
				}
			case len(r.options.Templates) > 0:
				effectiveTemplatePaths = globalTemplatePaths
				restrictTemplates = true
			default:
				effectiveTemplatePaths = defaultTemplatePaths
				restrictTemplates = true
			}
		}

		filter.Prepare(
			append([]string(nil), effectiveTags...),
			append([]string(nil), effectiveExcludeTags...),
			effectiveSeverities,
			effectiveTemplatePaths,
			globalIncludeTemplatePaths,
			restrictTemplates,
		)
	}

	if hasTemplateOverrides {
		templates := sortedKeys(unionTemplatePaths)
		if loadDefaultTemplates {
			templates = append([]string{config.DefaultConfig.TemplatesDirectory}, templates...)
		}
		loaderConfig.Templates = templates
	}
	return nil
}

// resolveTargetTemplatePaths resolves template selectors to on-disk paths.
// When enforceLocalContainment is set (per-target JSONL selectors), a selector
// may not escape the templates tree via an absolute path or parent-directory
// traversal. Global -t/-it selectors are trusted CLI input and are resolved
// without that restriction so their documented arbitrary-path behavior is kept.
func resolveTargetTemplatePaths(templateCatalog catalog.Catalog, selectors []string, sourceLine int, enforceLocalContainment bool) ([]string, error) {
	for _, selector := range selectors {
		parsed, err := url.Parse(selector)
		if err == nil && parsed.IsAbs() && (parsed.Scheme == "http" || parsed.Scheme == "https") {
			location := "global options"
			if sourceLine > 0 {
				location = fmt.Sprintf("jsonl line %d", sourceLine)
			}
			return nil, fmt.Errorf("%s: remote template selector %q is not supported with per-target template overrides", location, selector)
		}
		if enforceLocalContainment && selectorEscapesTemplatesTree(selector) {
			location := "template selector"
			if sourceLine > 0 {
				location = fmt.Sprintf("jsonl line %d template selector", sourceLine)
			}
			return nil, fmt.Errorf("%s %q must stay within the templates directory; absolute paths and parent-directory traversal are not allowed", location, selector)
		}
	}

	paths, pathErrors := templateCatalog.GetTemplatesPath(selectors)
	if len(pathErrors) > 0 {
		keys := make([]string, 0, len(pathErrors))
		for selector := range pathErrors {
			keys = append(keys, selector)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, selector := range keys {
			parts = append(parts, fmt.Sprintf("%s: %v", selector, pathErrors[selector]))
		}
		prefix := "template selector"
		if sourceLine > 0 {
			prefix = fmt.Sprintf("jsonl line %d template selector", sourceLine)
		}
		return nil, fmt.Errorf("%s could not be resolved: %s", prefix, strings.Join(parts, "; "))
	}
	if len(paths) == 0 {
		prefix := "template selectors"
		if sourceLine > 0 {
			prefix = fmt.Sprintf("jsonl line %d templates", sourceLine)
		}
		return nil, fmt.Errorf("%s did not match any templates", prefix)
	}

	unique := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		unique[filepath.Clean(path)] = struct{}{}
	}
	return sortedKeys(unique), nil
}

// selectorEscapesTemplatesTree reports whether a per-target template selector
// would resolve outside the templates directory. Both vectors are rejected at
// the input boundary, before any filesystem resolution touches the path: an
// absolute path (returned as-is by DiskCatalog.ResolvePath) and a relative path
// whose cleaned form climbs out of the tree via "..".
func selectorEscapesTemplatesTree(selector string) bool {
	if filepath.IsAbs(selector) {
		return true
	}
	cleaned := filepath.ToSlash(filepath.Clean(selector))
	return cleaned == ".." || strings.HasPrefix(cleaned, "../")
}

func canonicalTargetSelectors(selectors []string) string {
	values := append([]string(nil), selectors...)
	sort.Strings(values)
	return strings.Join(values, "\x00")
}

func removeIncludedTags(excluded, included []string) []string {
	includedSet := make(map[string]struct{}, len(included))
	for _, tag := range included {
		includedSet[strings.ToLower(strings.TrimSpace(tag))] = struct{}{}
	}

	result := make([]string, 0, len(excluded))
	seen := make(map[string]struct{}, len(excluded))
	for _, tag := range excluded {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" {
			continue
		}
		if _, allowed := includedSet[tag]; allowed {
			continue
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		result = append(result, tag)
	}
	return result
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func targetFilterFor(input *contextargs.MetaInput) *contextargs.TargetFilter {
	if input == nil {
		return nil
	}
	return input.TargetFilter
}
