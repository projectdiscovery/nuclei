package profile

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	"github.com/projectdiscovery/utils/errkit"
	"github.com/projectdiscovery/utils/generic"
	"gopkg.in/yaml.v3"
)

// Profile represents a nuclei template profile configuration
// It extends the standard config format with metadata and embedded secrets
type Profile struct {
	// Profile metadata fields (ignored by goflags but useful for documentation)
	ID          string         `yaml:"id,omitempty" json:"id,omitempty"`
	Name        string         `yaml:"name,omitempty" json:"name,omitempty"`
	Description string         `yaml:"description,omitempty" json:"description,omitempty"`
	Purpose     string         `yaml:"purpose,omitempty" json:"purpose,omitempty"`
	Author      string         `yaml:"author,omitempty" json:"author,omitempty"`
	Version     string         `yaml:"version,omitempty" json:"version,omitempty"`
	Tags        []string       `yaml:"profile-tags,omitempty" json:"profile-tags,omitempty"`
	Secrets     *SecretsConfig `yaml:"secrets,omitempty" json:"secrets,omitempty"`

	// RawConfig holds all other fields that are passed to goflags
	RawConfig map[string]interface{} `yaml:"-" json:"-"`
}

// SecretsConfig holds embedded secrets configuration
type SecretsConfig struct {
	Static  []authx.Secret  `yaml:"static,omitempty" json:"static,omitempty"`
	Dynamic []authx.Dynamic `yaml:"dynamic,omitempty" json:"dynamic,omitempty"`
}

// Info returns the profile information
type Info struct {
	ID          string
	Name        string
	Description string
	Purpose     string
	Author      string
	Version     string
	Tags        []string
}

// GetInfo returns the profile metadata info
func (p *Profile) GetInfo() Info {
	return Info{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		Purpose:     p.Purpose,
		Author:      p.Author,
		Version:     p.Version,
		Tags:        p.Tags,
	}
}

// HasSecrets returns true if the profile has embedded secrets
func (p *Profile) HasSecrets() bool {
	return p.Secrets != nil && (len(p.Secrets.Static) > 0 || len(p.Secrets.Dynamic) > 0)
}

// GetAuthx returns the embedded secrets as an Authx struct
// Creates defensive copies of slices to prevent unexpected mutations
func (p *Profile) GetAuthx() *authx.Authx {
	if !p.HasSecrets() {
		return nil
	}

	// Create defensive copies of slices to prevent mutations
	staticCopy := make([]authx.Secret, len(p.Secrets.Static))
	copy(staticCopy, p.Secrets.Static)

	dynamicCopy := make([]authx.Dynamic, len(p.Secrets.Dynamic))
	copy(dynamicCopy, p.Secrets.Dynamic)

	return &authx.Authx{
		ID: p.ID,
		Info: authx.AuthFileInfo{
			Name:        p.Name,
			Description: p.Description,
			Author:      p.Author,
		},
		Secrets: staticCopy,
		Dynamic: dynamicCopy,
	}
}

// LoadProfile loads a profile from a file
func LoadProfile(filePath string) (*Profile, error) {
	ext := filepath.Ext(filePath)
	if !generic.EqualsAny(ext, ".yml", ".yaml") {
		return nil, errkit.New("invalid file extension: supported extensions are .yml and .yaml got %s", ext)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, errkit.Wrap(err, "failed to read profile file")
	}

	return ParseProfile(data)
}

// ParseProfile parses profile data from bytes
func ParseProfile(data []byte) (*Profile, error) {
	var profile Profile

	// First parse all fields into a map to preserve unknown fields for goflags
	var rawData map[string]interface{}
	if err := yaml.Unmarshal(data, &rawData); err != nil {
		return nil, errkit.Wrap(err, "failed to parse profile yaml")
	}

	// Parse the known profile fields
	if err := yaml.Unmarshal(data, &profile); err != nil {
		return nil, errkit.Wrap(err, "failed to parse profile")
	}

	// Store raw config for passing to goflags (excludes profile-specific fields)
	profile.RawConfig = make(map[string]interface{})
	excludedKeys := map[string]bool{
		"id": true, "name": true, "description": true, "purpose": true,
		"author": true, "version": true, "profile-tags": true, "secrets": true,
	}

	for key, value := range rawData {
		if !excludedKeys[key] {
			profile.RawConfig[key] = value
		}
	}

	return &profile, nil
}

// WriteConfigForGoflags writes a temporary config file containing only
// the goflags-compatible fields (excludes profile metadata and secrets)
func (p *Profile) WriteConfigForGoflags(tmpDir string) (string, error) {
	if len(p.RawConfig) == 0 {
		return "", nil
	}

	data, err := yaml.Marshal(p.RawConfig)
	if err != nil {
		return "", errkit.Wrap(err, "failed to marshal profile config")
	}

	tmpFile, err := os.CreateTemp(tmpDir, "nuclei-profile-*.yaml")
	if err != nil {
		return "", errkit.Wrap(err, "failed to create temp profile file")
	}
	defer tmpFile.Close()

	if _, err := tmpFile.Write(data); err != nil {
		return "", errkit.Wrap(err, "failed to write temp profile file")
	}

	return tmpFile.Name(), nil
}

// ValidateSecrets validates the embedded secrets configuration
func (p *Profile) ValidateSecrets() error {
	if !p.HasSecrets() {
		return nil
	}

	for i, secret := range p.Secrets.Static {
		if err := secret.Validate(); err != nil {
			return errkit.Wrap(err, fmt.Sprintf("invalid static secret at index %d", i))
		}
	}

	for i, dynamic := range p.Secrets.Dynamic {
		if err := dynamic.Validate(); err != nil {
			return errkit.Wrap(err, fmt.Sprintf("invalid dynamic secret at index %d", i))
		}
	}

	return nil
}
