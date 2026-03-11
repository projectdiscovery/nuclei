// Package profile implements template profile loading, validation, and materialization
// for nuclei's template-profile feature (issue #5567).
//
// A template profile is a YAML file that bundles nuclei flags together with optional
// metadata fields (id, name, purpose, description) and inline targets/secrets that
// would otherwise require separate files.
//
// Example profile:
//
//	id: my-scan
//	name: My Scan Profile
//	purpose: Daily vuln scan of example.com
//	description: Runs CVE templates against example.com
//
//	# Inline target list (materialized to a temp file)
//	list: |
//	  example.com
//	  api.example.com
//
//	tags: cve
//	exclude-tags: dos,fuzz
//
//	# Inline secrets block (materialized to a temp file)
//	secrets:
//	  static:
//	    - type: header
//	      domains:
//	        - api.example.com
//	      headers:
//	        - key: X-API-Key
//	          value: secret-here
package profile

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Metadata holds informational fields that are stripped before passing the
// profile to goflags.MergeConfigFile.  These fields are intentionally ignored
// by the flag-merge step so users can annotate profiles freely.
type Metadata struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Purpose     string `yaml:"purpose"`
	Description string `yaml:"description"`
}

// Profile represents the parsed content of a template-profile YAML file.
// It separates the nuclei-flag section from the metadata, inline-target list,
// and inline-secrets block so each piece can be handled appropriately.
type Profile struct {
	Metadata

	// InlineTargets is the content of the "list" key.  If non-empty it will
	// be materialized into a temporary file and added to the input list.
	InlineTargets string `yaml:"list"`

	// InlineSecrets is the raw YAML value of the "secrets" key.  When present
	// it is written to a temp file and appended to options.SecretsFile.
	InlineSecrets interface{} `yaml:"secrets"`

	// FlagOverrides holds every OTHER key in the profile so we can re-serialise
	// a "clean" version without the metadata/list/secrets keys for goflags.
	FlagOverrides map[string]interface{} `yaml:"-"`

	// tempFiles tracks temp files created during materialization so callers
	// can clean them up on exit.
	tempFiles []string
}

// Load reads a profile YAML file, validates it, and returns a Profile.
func Load(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read profile %q: %w", path, err)
	}
	return Parse(data, path)
}

// Parse decodes raw YAML profile bytes.  path is used only for error messages.
func Parse(data []byte, path string) (*Profile, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("profile %q is empty", path)
	}

	// First pass: decode into a generic map so we can extract metadata and
	// special keys without strict schema enforcement (extra fields are fine).
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("could not parse profile %q: %w", path, err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("profile %q is empty", path)
	}

	p := &Profile{}

	// Extract metadata fields (silently ignored by goflags merge).
	if v, ok := rawString(raw, "id"); ok {
		p.ID = v
	}
	if v, ok := rawString(raw, "name"); ok {
		p.Name = v
	}
	if v, ok := rawString(raw, "purpose"); ok {
		p.Purpose = v
	}
	if v, ok := rawString(raw, "description"); ok {
		p.Description = v
	}

	// Extract inline target list.
	// Reject non-string values (e.g. YAML sequences) so targets do not
	// silently disappear when the profile is misformatted.
	if v, ok := raw["list"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("profile field %q must be a string (got %T); use a YAML block scalar (|) for multi-line targets", "list", v)
		}
		p.InlineTargets = s
	}

	// Extract inline secrets block (preserve as-is for re-serialization).
	if v, ok := raw["secrets"]; ok {
		p.InlineSecrets = v
	}

	// Build flag-overrides map: everything except our reserved keys.
	reserved := map[string]bool{
		"id": true, "name": true, "purpose": true, "description": true,
		"list": true, "secrets": true,
	}
	p.FlagOverrides = make(map[string]interface{}, len(raw))
	for k, v := range raw {
		if !reserved[k] {
			p.FlagOverrides[k] = v
		}
	}

	return p, nil
}

// Validate checks that the profile is well-formed.  It returns a descriptive
// error listing all problems found so users can fix them in one go.
func (p *Profile) Validate() error {
	var errs []string

	if p.ID != "" && strings.ContainsAny(p.ID, " /\\") {
		errs = append(errs, "id must not contain spaces or path separators")
	}

	// If there are inline secrets, make sure they look like a map (not a scalar).
	if p.InlineSecrets != nil {
		if _, ok := p.InlineSecrets.(map[string]interface{}); !ok {
			errs = append(errs, "secrets must be a YAML mapping (expected static/dynamic keys)")
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid profile: %s", strings.Join(errs, "; "))
	}
	return nil
}

// MaterializeTargets writes inline targets to a temporary file and returns its
// path.  Returns ("", nil) if there are no inline targets.  The temp file is
// registered for cleanup via TempFiles().
func (p *Profile) MaterializeTargets(dir string) (string, error) {
	if p.InlineTargets == "" {
		return "", nil
	}

	f, err := os.CreateTemp(dir, "nuclei-profile-targets-*.txt")
	if err != nil {
		return "", fmt.Errorf("could not create targets temp file: %w", err)
	}
	defer f.Close()

	// Write one target per non-empty line, trimming whitespace.
	for _, line := range strings.Split(p.InlineTargets, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, err := fmt.Fprintln(f, line); err != nil {
			return "", fmt.Errorf("could not write targets temp file: %w", err)
		}
	}

	p.tempFiles = append(p.tempFiles, f.Name())
	return f.Name(), nil
}

// MaterializeSecrets writes the inline secrets block to a temporary YAML file
// and returns its path.  Returns ("", nil) if there are no inline secrets.
func (p *Profile) MaterializeSecrets(dir string) (string, error) {
	if p.InlineSecrets == nil {
		return "", nil
	}

	secretsYAML, err := yaml.Marshal(p.InlineSecrets)
	if err != nil {
		return "", fmt.Errorf("could not serialize inline secrets: %w", err)
	}

	f, err := os.CreateTemp(dir, "nuclei-profile-secrets-*.yaml")
	if err != nil {
		return "", fmt.Errorf("could not create secrets temp file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(secretsYAML); err != nil {
		return "", fmt.Errorf("could not write secrets temp file: %w", err)
	}

	p.tempFiles = append(p.tempFiles, f.Name())
	return f.Name(), nil
}

// WriteFlagsFile serializes the FlagOverrides (the nuclei flags portion of the
// profile, stripped of metadata/list/secrets) to a temporary YAML file so it
// can be passed to goflags.MergeConfigFile.  This avoids parse errors that
// goflags would emit when encountering the extra metadata keys.
//
// Returns the path of the temp file, or ("", nil) if FlagOverrides is empty.
func (p *Profile) WriteFlagsFile(dir string) (string, error) {
	if len(p.FlagOverrides) == 0 {
		return "", nil
	}

	flagsYAML, err := yaml.Marshal(p.FlagOverrides)
	if err != nil {
		return "", fmt.Errorf("could not serialize profile flags: %w", err)
	}

	f, err := os.CreateTemp(dir, "nuclei-profile-flags-*.yaml")
	if err != nil {
		return "", fmt.Errorf("could not create profile flags temp file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(flagsYAML); err != nil {
		return "", fmt.Errorf("could not write profile flags temp file: %w", err)
	}

	p.tempFiles = append(p.tempFiles, f.Name())
	return f.Name(), nil
}

// TempFiles returns the paths of all temporary files created during
// materialization.  Callers should remove these on exit.
func (p *Profile) TempFiles() []string {
	return p.tempFiles
}

// Summary returns a human-readable one-liner describing the profile.
func (p *Profile) Summary() string {
	var parts []string
	if p.Name != "" {
		parts = append(parts, p.Name)
	} else if p.ID != "" {
		parts = append(parts, p.ID)
	}
	if p.Purpose != "" {
		parts = append(parts, "("+p.Purpose+")")
	}
	if len(parts) == 0 {
		return "(unnamed profile)"
	}
	return strings.Join(parts, " ")
}

// ListProfiles walks profilesDir and returns one entry per YAML profile found.
// Each entry is a ListEntry with the relative path from templatesRootDir and
// the derived profile ID (filename without extension).
type ListEntry struct {
	RelPath   string
	ProfileID string
	Metadata  Metadata
}

// ListProfiles walks profilesDir and returns metadata for every YAML profile.
func ListProfiles(profilesDir, templatesRootDir string) ([]ListEntry, error) {
	var entries []ListEntry
	err := filepath.WalkDir(profilesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == profilesDir {
				// Root directory is missing or unreadable — surface the error so
				// callers can distinguish "no profiles" from "bad profiles path".
				return err
			}
			return nil // skip individual unreadable sub-entries
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}

		relPath, _ := filepath.Rel(templatesRootDir, path)
		profileID := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))

		entry := ListEntry{
			RelPath:   relPath,
			ProfileID: profileID,
		}

		// Best-effort metadata load — if parse fails just omit metadata.
		if p, loadErr := Load(path); loadErr == nil {
			entry.Metadata = p.Metadata
			if entry.Metadata.ID == "" {
				entry.Metadata.ID = profileID
			}
		}

		entries = append(entries, entry)
		return nil
	})
	return entries, err
}

// rawString is a helper that returns a string value from a raw map.
func rawString(m map[string]interface{}, key string) (string, bool) {
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}
