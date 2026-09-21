// Package targetprofile binds template selections to individual targets, so a
// single scan can run a different profile on each target.
//
// A target line is a JSON object whose keys mirror template profiles and CLI
// flags:
//
//	{"target": "https://a.example", "tags": ["thinkphp"], "tech": ["php"]}
//	{"target": "https://b.example", "profile": "wordpress", "severity": ["high"]}
package targetprofile

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/internal/configuration"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
)

const (
	keyTarget  = "target"
	keyProfile = "profile"

	keyTemplates       = "templates"
	keyTags            = "tags"
	keyExcludeTags     = "exclude-tags"
	keyIncludeTags     = "include-tags"
	keyAuthor          = "author"
	keyTemplateID      = "template-id"
	keyExcludeID       = "exclude-id"
	keySeverity        = "severity"
	keyExcludeSeverity = "exclude-severity"
	keyType            = "type"
	keyExcludeType     = "exclude-type"
	keyTech            = "tech"
)

// selectorKeys are the template selection keys a target line or profile may set.
var selectorKeys = []string{
	keyTemplates, keyTags, keyExcludeTags, keyIncludeTags, keyAuthor, keyTemplateID,
	keyExcludeID, keySeverity, keyExcludeSeverity, keyType, keyExcludeType, keyTech,
}

// selector is a raw template selection keyed by selector key.
type selector map[string][]string

// IsLine reports whether an input line is a target line rather than a plain target.
func IsLine(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "{")
}

// parseLine decodes a target line. Unknown keys are rejected so that a typo
// cannot silently widen the scan to every template.
func parseLine(line string) (target, profile string, sel selector, err error) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return "", "", nil, fmt.Errorf("invalid target line %q: %w", line, err)
	}

	target, err = stringValue(raw, keyTarget)
	if err != nil {
		return "", "", nil, err
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return "", "", nil, fmt.Errorf("target line %q has no %q", line, keyTarget)
	}

	profile, err = stringValue(raw, keyProfile)
	if err != nil {
		return "", "", nil, err
	}
	delete(raw, keyTarget)
	delete(raw, keyProfile)

	sel, ignored, err := toSelector(raw)
	if err != nil {
		return "", "", nil, fmt.Errorf("target %q: %w", target, err)
	}
	if len(ignored) > 0 {
		return "", "", nil, fmt.Errorf("target %q: unknown keys %s (supported: target, profile, %s)", target, strings.Join(ignored, ", "), strings.Join(selectorKeys, ", "))
	}
	return target, profile, sel, nil
}

// loadProfile reads the selection keys of a template profile. Keys that
// configure the whole scan (code, var, rate limits...) cannot apply to a single
// target and are returned as ignored.
func loadProfile(profile, templatesDir string) (selector, []string, error) {
	path, err := configuration.ResolveProfilePath(profile, templatesDir)
	if err != nil {
		return nil, nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read profile %q: %w", path, err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("parse profile %q: %w", path, err)
	}
	sel, ignored, err := toSelector(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("profile %q: %w", path, err)
	}
	return sel, ignored, nil
}

// toSelector extracts selector keys from raw, returning the other keys as ignored.
func toSelector(raw map[string]any) (selector, []string, error) {
	sel := selector{}
	var ignored []string
	for key, value := range raw {
		if !slices.Contains(selectorKeys, key) {
			ignored = append(ignored, key)
			continue
		}
		values, err := stringList(value)
		if err != nil {
			return nil, nil, fmt.Errorf("key %q: %w", key, err)
		}
		if len(values) > 0 {
			sel[key] = values
		}
	}
	slices.Sort(ignored)
	return sel, ignored, nil
}

// merge returns base overridden by the keys set in override, the same way
// CLI flags override a profile.
func (base selector) merge(override selector) selector {
	merged := make(selector, len(base)+len(override))
	for key, values := range base {
		merged[key] = values
	}
	for key, values := range override {
		merged[key] = values
	}
	return merged
}

func stringValue(raw map[string]any, key string) (string, error) {
	value, ok := raw[key]
	if !ok || value == nil {
		return "", nil
	}
	str, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("key %q must be a string", key)
	}
	return str, nil
}

// stringList accepts a comma-separated string or a list of strings, matching
// how the equivalent CLI flags and profile keys are written.
func stringList(value any) ([]string, error) {
	var items []string
	switch v := value.(type) {
	case nil:
	case string:
		items = strings.Split(v, ",")
	case []any:
		for _, item := range v {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("expected strings, got %T", item)
			}
			items = append(items, str)
		}
	default:
		return nil, fmt.Errorf("expected a string or a list of strings, got %T", value)
	}

	values := make([]string, 0, len(items))
	for _, item := range items {
		if item = strings.TrimSpace(item); item != "" {
			values = append(values, item)
		}
	}
	return values, nil
}
