package index

import (
	"os"
	"slices"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
)

// Metadata contains lightweight metadata extracted from a template.
type Metadata struct {
	// ID is the unique identifier of the template.
	ID string `gob:"id"`

	// FilePath is the path to the template file.
	FilePath string `gob:"file_path"`

	// ModTime is the modification time of the template file.
	ModTime time.Time `gob:"mod_time"`

	// Name is the name of the template.
	Name string `gob:"name"`

	// Authors are the authors of the template.
	Authors []string `gob:"authors"`

	// Tags are the tags associated with the template.
	Tags []string `gob:"tags"`

	// Severity is the severity level of the template.
	Severity string `gob:"severity"`

	// ProtocolType is the primary protocol type of the template.
	ProtocolType string `gob:"protocol_type"`

	// Verified indicates whether the template is verified.
	Verified bool `gob:"verified"`

	// TemplateVerifier is the verifier used for the template.
	TemplateVerifier string `gob:"verifier,omitempty"`

	// NOTE(dwisiswant0): Consider adding more fields here in the future to
	// enhance filtering caps w/o loading full templates, such as:
	// `has_{code,headless,file}` to indicate presence of protocol-based
	// requests, and/or classification fields (CVE, CWE, CVSS, EPSS), if needed.
	//
	// For maintainers: when adding new fields, don't forget to update the
	// Weigher logic in [NewIndex] to account for the new fields in cache weight
	// calculation, because it affects cache eviction behavior. Also, consider
	// the impact on existing cached data and whether a [IndexVersion] bump is
	// needed.
}

// NewMetadataFromTemplate creates a new metadata object from a template.
func NewMetadataFromTemplate(path string, tpl *templates.Template) *Metadata {
	return &Metadata{
		ID:       tpl.ID,
		FilePath: path,

		Name:     tpl.Info.Name,
		Authors:  tpl.Info.Authors.ToSlice(),
		Tags:     tpl.Info.Tags.ToSlice(),
		Severity: tpl.Info.SeverityHolder.Severity.String(),

		ProtocolType: tpl.Type().String(),

		Verified:         tpl.Verified,
		TemplateVerifier: tpl.TemplateVerifier,
	}
}

// IsValid checks if the cached metadata is still valid by comparing the file
// modification time.
func (m *Metadata) IsValid() bool {
	info, err := os.Stat(m.FilePath)
	if err != nil {
		return false
	}

	return m.ModTime.Equal(info.ModTime())
}

// MatchesSeverity checks if the metadata matches the given severity.
func (m *Metadata) MatchesSeverity(sev severity.Severity) bool {
	return m.Severity == sev.String()
}

// MatchesProtocol checks if the metadata matches the given protocol type.
func (m *Metadata) MatchesProtocol(protocolType types.ProtocolType) bool {
	return m.ProtocolType == protocolType.String()
}

// HasTag checks if the metadata contains the given tag.
func (m *Metadata) HasTag(tag string) bool {
	return slices.Contains(m.Tags, tag)
}

// HasAuthor checks if the metadata contains the given author.
func (m *Metadata) HasAuthor(author string) bool {
	return slices.Contains(m.Authors, author)
}
