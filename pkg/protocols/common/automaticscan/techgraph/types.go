// Package techgraph builds the offline technology->template mapping artifact
// (tech-graph.json) consumed by automatic scan v2. See AUTOMATIC_SCAN_V2.md.
package techgraph

// ArtifactVersion is the schema version of the emitted artifact.
const ArtifactVersion = 1

// Tier gates how aggressively a template is selected at runtime.
type Tier string

const (
	TierLean     Tier = "lean"
	TierBalanced Tier = "balanced"
	TierThorough Tier = "thorough"
)

// Graph is the top-level tech-graph artifact.
type Graph struct {
	Version     int               `json:"version"`
	GeneratedAt string            `json:"generated_at"`
	SourceHash  string            `json:"source_hash,omitempty"`
	Techs       map[string]*Tech  `json:"techs"`
	Baseline    []BaselineEntry   `json:"baseline"`
	Detection   []DetectionEntry  `json:"detection"`
	Synonyms    map[string]string `json:"synonyms"`
	Stats       Stats             `json:"stats"`
}

// DetectionEntry is a phase-1 detector template (tagged tech/detect/favicon).
// Running these fingerprints the target before selection.
type DetectionEntry struct {
	ID   string `json:"id"`
	Tech string `json:"tech,omitempty"` // canonical tech this detector anchors, if any
}

// Tech is a single canonical technology and the templates that depend on it.
type Tech struct {
	ID        string        `json:"id"`
	Vendor    string        `json:"vendor,omitempty"`
	Product   string        `json:"product,omitempty"`
	CPE       string        `json:"cpe,omitempty"`
	Aliases   []string      `json:"aliases,omitempty"`
	Templates []TemplateRef `json:"templates"`
}

// TemplateRef references a template that depends on a tech.
type TemplateRef struct {
	ID       string `json:"id"`
	Category string `json:"category,omitempty"`
	Severity string `json:"severity,omitempty"`
	// Product is the original sub-product when attached to a platform node via
	// platform grouping (e.g. plugin "wp-optimize" under platform "wordpress").
	Product string `json:"product,omitempty"`
	// Source records how the template was attached: "cpe", "platform", "tag".
	Source string `json:"source,omitempty"`
	// VersionRange is reserved for the AI version-parsing milestone. Empty means
	// "fire regardless of detected version".
	VersionRange string `json:"version_range,omitempty"`
}

// BaselineEntry is a tech-agnostic template that runs on every applicable target.
type BaselineEntry struct {
	ID       string `json:"id"`
	Category string `json:"category,omitempty"`
	Severity string `json:"severity,omitempty"`
	Tier     Tier   `json:"tier"`
}

// Stats summarises a build run.
type Stats struct {
	Total          int `json:"total"`
	Dependents     int `json:"dependents"`
	DependentsCPE  int `json:"dependents_cpe"`
	DependentsPlat int `json:"dependents_platform"`
	DependentsDir  int `json:"dependents_dir"`
	DependentsTag  int `json:"dependents_tag"`
	DependentsID   int `json:"dependents_id"`
	Baseline       int `json:"baseline"`
	Detection      int `json:"detection"`
	Excluded       int `json:"excluded"`
	Unmapped       int `json:"unmapped"`
	Techs          int `json:"techs"`
	ParseError     int `json:"parse_error"`
}
