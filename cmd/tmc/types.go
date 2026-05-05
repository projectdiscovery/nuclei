package main

type Mark struct {
	Name     string `json:"name,omitempty"`
	Position int    `json:"position,omitempty"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
	Snippet  string `json:"snippet,omitempty"`
}

type Error struct {
	Name string `json:"name"`
	Mark Mark   `json:"mark"`
}

type LintError struct {
	Name   string `json:"name,omitempty"`
	Reason string `json:"reason,omitempty"`
	Mark   Mark   `json:"mark,omitempty"`
}

type TemplateLintResp struct {
	Input     string    `json:"template_input,omitempty"`
	Lint      bool      `json:"template_lint,omitempty"`
	LintError LintError `json:"lint_error,omitempty"`
}

type ValidateError struct {
	Location string      `json:"location,omitempty"`
	Message  string      `json:"message,omitempty"`
	Name     string      `json:"name,omitempty"`
	Argument interface{} `json:"argument,omitempty"`
	Stack    string      `json:"stack,omitempty"`
	Mark     struct {
		Line   int `json:"line,omitempty"`
		Column int `json:"column,omitempty"`
		Pos    int `json:"pos,omitempty"`
	} `json:"mark,omitempty"`
}

// TemplateResponse from templateman to be used for enhancing and formatting
type TemplateResp struct {
	Input              string          `json:"template_input,omitempty"`
	Format             bool            `json:"template_format,omitempty"`
	Updated            string          `json:"updated_template,omitempty"`
	Enhance            bool            `json:"template_enhance,omitempty"`
	Enhanced           string          `json:"enhanced_template,omitempty"`
	Lint               bool            `json:"template_lint,omitempty"`
	LintError          LintError       `json:"lint_error,omitempty"`
	Validate           bool            `json:"template_validate,omitempty"`
	ValidateErrorCount int             `json:"validate_error_count,omitempty"`
	ValidateError      []ValidateError `json:"validate_error,omitempty"`
	Error              Error           `json:"error,omitempty"`
}

// InfoBlock Cloning struct from nuclei as we don't want any validation
type InfoBlock struct {
	Info TemplateInfo `yaml:"info"`
}

type TemplateClassification struct {
	CvssMetrics string  `yaml:"cvss-metrics,omitempty"`
	CvssScore   float64 `yaml:"cvss-score,omitempty"`
	CveId       string  `yaml:"cve-id,omitempty"`
	CweId       string  `yaml:"cwe-id,omitempty"`
	Cpe         string  `yaml:"cpe,omitempty"`
	EpssScore   float64 `yaml:"epss-score,omitempty"`
}

type TemplateInfo struct {
	Name           string                 `yaml:"name"`
	Author         string                 `yaml:"author"`
	Severity       string                 `yaml:"severity,omitempty"`
	Description    string                 `yaml:"description,omitempty"`
	Reference      interface{}            `yaml:"reference,omitempty"`
	Remediation    string                 `yaml:"remediation,omitempty"`
	Classification TemplateClassification `yaml:"classification,omitempty"`
	Metadata       map[string]interface{} `yaml:"metadata,omitempty"`
	Tags           string                 `yaml:"tags,omitempty"`
}
