package config

import (
	"gopkg.in/yaml.v3"
)

// TemplateProfile represents a template profile configuration
type TemplateProfile struct {
	// Metadata fields (ignored during processing)
	Name        string `yaml:"name,omitempty"`
	Purpose     string `yaml:"purpose,omitempty"`
	Description string `yaml:"description,omitempty"`
	ID          string `yaml:"id,omitempty"`

	// Targets
	List string `yaml:"list,omitempty"`

	// Template config
	Type       []string `yaml:"type,omitempty"`
	ExcludeTags []string `yaml:"exclude-tags,omitempty"`

	// Options
	TemplateConcurrency int  `yaml:"template-concurrency,omitempty"`
	HostConcurrency     int  `yaml:"host-concurrency,omitempty"`
	Stats               bool `yaml:"stats,omitempty"`
	Timeout             int  `yaml:"timeout,omitempty"`

	// Secrets (embedded auth data)
	Secrets SecretsConfig `yaml:"secrets,omitempty"`

	// Extra fields are ignored but allowed
	// This enables metadata without comments
}

// SecretsConfig holds embedded authentication secrets
type SecretsConfig struct {
	Static  []StaticSecret  `yaml:"static,omitempty"`
	Dynamic []DynamicSecret `yaml:"dynamic,omitempty"`
}

// StaticSecret represents a static secret (API keys, headers, etc.)
type StaticSecret struct {
	Type     string   `yaml:"type,omitempty"`
	Domains  []string `yaml:"domains,omitempty"`
	Headers  []Header `yaml:"headers,omitempty"`
	Cookies  []Cookie `yaml:"cookies,omitempty"`
}

// Header represents an HTTP header
type Header struct {
	Key   string `yaml:"key,omitempty"`
	Value string `yaml:"value,omitempty"`
}

// Cookie represents an HTTP cookie
type Cookie struct {
	Name  string `yaml:"name,omitempty"`
	Value string `yaml:"value,omitempty"`
}

// DynamicSecret represents a dynamic secret (OAuth flows, etc.)
type DynamicSecret struct {
	Template  string            `yaml:"template,omitempty"`
	Variables []SecretVariable  `yaml:"variables,omitempty"`
	Type      string            `yaml:"type,omitempty"`
	Domains   []string          `yaml:"domains,omitempty"`
	Headers   []Header          `yaml:"headers,omitempty"`
}

// SecretVariable represents a variable in a dynamic secret
type SecretVariable struct {
	Name  string `yaml:"name,omitempty"`
	Value string `yaml:"value,omitempty"`
}

// UnmarshalYAML implements custom YAML unmarshaling
// This allows ignoring extra fields gracefully
func (tp *TemplateProfile) UnmarshalYAML(value *yaml.Node) error {
	type Alias TemplateProfile
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(tp),
	}
	
	// Decode known fields
	if err := value.Decode(aux); err != nil {
		return err
	}
	
	// Extra fields are automatically ignored by yaml package
	// This enables metadata fields like 'id', 'name', 'purpose' without errors
	
	return nil
}
