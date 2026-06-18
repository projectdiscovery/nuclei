package techgraph

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// templateInfo is the subset of a nuclei template we need for graph building.
// We deliberately avoid the full template parser: only the info block is read,
// which keeps the generator fast and dependency-light over ~13k files.
type templateInfo struct {
	ID       string
	Name     string
	Severity string
	Category string // derived from directory (cves, exposed-panels, ...)
	Subdir   string // directory under the category (e.g. "aem" in misconfiguration/aem/)
	Tags     []string
	Vendor   string
	Product  string
	CPE      string
}

// rawTemplate mirrors the YAML structure for lenient decoding.
type rawTemplate struct {
	ID   string `yaml:"id"`
	Info struct {
		Name           string         `yaml:"name"`
		Severity       string         `yaml:"severity"`
		Tags           any            `yaml:"tags"`
		Metadata       map[string]any `yaml:"metadata"`
		Classification struct {
			CPE string `yaml:"cpe"`
		} `yaml:"classification"`
	} `yaml:"info"`
}

// extractTemplate reads a single template file and returns its info subset.
// ok is false when the file is not a parseable template (e.g. workflow, helper).
func extractTemplate(path, root string) (templateInfo, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return templateInfo{}, false
	}
	var raw rawTemplate
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return templateInfo{}, false
	}
	if raw.ID == "" {
		return templateInfo{}, false
	}

	category, subdir := derivePath(path, root)
	info := templateInfo{
		ID:       raw.ID,
		Name:     raw.Info.Name,
		Severity: strings.ToLower(strings.TrimSpace(raw.Info.Severity)),
		Category: category,
		Subdir:   subdir,
		Tags:     coerceStringSlice(raw.Info.Tags),
		CPE:      strings.TrimSpace(raw.Info.Classification.CPE),
	}

	if raw.Info.Metadata != nil {
		info.Vendor = firstNonEmpty(coerceStringSlice(raw.Info.Metadata["vendor"]))
		info.Product = firstNonEmpty(coerceStringSlice(raw.Info.Metadata["product"]))
	}

	// Prefer CPE for vendor/product when metadata is missing.
	if cv, cp, ok := parseCPE(info.CPE); ok {
		if info.Vendor == "" {
			info.Vendor = cv
		}
		if info.Product == "" {
			info.Product = cp
		}
	}
	return info, true
}

// derivePath returns the nuclei category and the immediate subdirectory under
// it, e.g. http/misconfiguration/aem/x.yaml -> ("misconfiguration", "aem").
// The subdir is often a product grouping and is used as a tech signal.
func derivePath(path, root string) (category, subdir string) {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	switch {
	case len(parts) >= 4:
		// protocol/category/subdir/.../file
		return parts[1], parts[2]
	case len(parts) == 3:
		return parts[1], ""
	case len(parts) == 2:
		return parts[0], ""
	default:
		return "", ""
	}
}

// parseCPE extracts vendor and product from CPE 2.3 (cpe:2.3:a:vendor:product:..)
// or CPE 2.2 URI (cpe:/a:vendor:product:..) forms.
func parseCPE(cpe string) (vendor, product string, ok bool) {
	cpe = strings.TrimSpace(cpe)
	if cpe == "" {
		return "", "", false
	}
	switch {
	case strings.HasPrefix(cpe, "cpe:2.3:"):
		parts := strings.Split(cpe, ":")
		// cpe:2.3:part:vendor:product:...
		if len(parts) >= 5 {
			return normToken(parts[3]), normToken(parts[4]), true
		}
	case strings.HasPrefix(cpe, "cpe:/"):
		parts := strings.Split(strings.TrimPrefix(cpe, "cpe:/"), ":")
		// part:vendor:product:...
		if len(parts) >= 3 {
			return normToken(parts[1]), normToken(parts[2]), true
		}
	}
	return "", "", false
}

// coerceStringSlice normalises tags/metadata values that may be a string, a
// comma-separated string, or a YAML list into a clean slice.
func coerceStringSlice(v any) []string {
	var out []string
	add := func(s string) {
		for _, part := range strings.Split(s, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	switch t := v.(type) {
	case string:
		add(t)
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok {
				add(s)
			}
		}
	case []string:
		for _, s := range t {
			add(s)
		}
	}
	return out
}

func firstNonEmpty(values []string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
