package index

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/stretchr/testify/require"
)

func TestFilterMatches(t *testing.T) {
	metadata := &Metadata{
		ID:           "test-template-1",
		FilePath:     "/templates/cves/2021/CVE-2021-1234.yaml",
		Name:         "Test CVE Template",
		Authors:      []string{"pdteam", "geeknik"},
		Tags:         []string{"cve", "rce", "apache"},
		Severity:     "critical",
		ProtocolType: "http",
	}

	t.Run("Empty filter matches all", func(t *testing.T) {
		filter := &Filter{}
		require.True(t, filter.Matches(metadata))
		require.True(t, filter.IsEmpty())
	})

	t.Run("Author filter - match", func(t *testing.T) {
		filter := &Filter{Authors: []string{"pdteam"}}
		require.True(t, filter.Matches(metadata))
	})

	t.Run("Author filter - no match", func(t *testing.T) {
		filter := &Filter{Authors: []string{"unknown"}}
		require.False(t, filter.Matches(metadata))
	})

	t.Run("Multiple authors - OR logic", func(t *testing.T) {
		filter := &Filter{Authors: []string{"unknown", "geeknik"}}
		require.True(t, filter.Matches(metadata))
	})

	t.Run("Tag filter - match", func(t *testing.T) {
		filter := &Filter{Tags: []string{"cve"}}
		require.True(t, filter.Matches(metadata))
	})

	t.Run("Tag filter - no match", func(t *testing.T) {
		filter := &Filter{Tags: []string{"xss"}}
		require.False(t, filter.Matches(metadata))
	})

	t.Run("Exclude tags - match", func(t *testing.T) {
		filter := &Filter{ExcludeTags: []string{"rce"}}
		require.False(t, filter.Matches(metadata))
	})

	t.Run("Include tags overrides exclude", func(t *testing.T) {
		filter := &Filter{
			ExcludeTags: []string{"rce"},
			IncludeTags: []string{"cve"},
		}
		require.True(t, filter.Matches(metadata))
	})

	t.Run("ID filter - exact match", func(t *testing.T) {
		filter := &Filter{IDs: []string{"test-template-1"}}
		require.True(t, filter.Matches(metadata))
	})

	t.Run("ID filter - wildcard match", func(t *testing.T) {
		filter := &Filter{IDs: []string{"test-*"}}
		require.True(t, filter.Matches(metadata))
	})

	t.Run("ID filter - no match", func(t *testing.T) {
		filter := &Filter{IDs: []string{"other-*"}}
		require.False(t, filter.Matches(metadata))
	})

	t.Run("Exclude ID - exact match", func(t *testing.T) {
		filter := &Filter{ExcludeIDs: []string{"test-template-1"}}
		require.False(t, filter.Matches(metadata))
	})

	t.Run("Exclude ID - wildcard match", func(t *testing.T) {
		filter := &Filter{ExcludeIDs: []string{"test-*"}}
		require.False(t, filter.Matches(metadata))
	})

	t.Run("Severity filter - match", func(t *testing.T) {
		filter := &Filter{Severities: []severity.Severity{severity.Critical}}
		require.True(t, filter.Matches(metadata))
	})

	t.Run("Severity filter - no match", func(t *testing.T) {
		filter := &Filter{Severities: []severity.Severity{severity.High, severity.Medium}}
		require.False(t, filter.Matches(metadata))
	})

	t.Run("Exclude severity - match", func(t *testing.T) {
		filter := &Filter{ExcludeSeverities: []severity.Severity{severity.Critical}}
		require.False(t, filter.Matches(metadata))
	})

	t.Run("Protocol type filter - match", func(t *testing.T) {
		filter := &Filter{ProtocolTypes: []types.ProtocolType{types.HTTPProtocol}}
		require.True(t, filter.Matches(metadata))
	})

	t.Run("Protocol type filter - no match", func(t *testing.T) {
		filter := &Filter{ProtocolTypes: []types.ProtocolType{types.DNSProtocol}}
		require.False(t, filter.Matches(metadata))
	})

	t.Run("Exclude protocol type - match", func(t *testing.T) {
		filter := &Filter{ExcludeProtocolTypes: []types.ProtocolType{types.HTTPProtocol}}
		require.False(t, filter.Matches(metadata))
	})

	t.Run("Include templates - path match", func(t *testing.T) {
		filter := &Filter{
			ExcludeTags:      []string{"cve"},
			IncludeTemplates: []string{"/templates/cves/"},
		}
		require.True(t, filter.Matches(metadata))
	})

	t.Run("Exclude templates - path match", func(t *testing.T) {
		filter := &Filter{
			ExcludeTemplates: []string{"/templates/cves/"},
		}
		require.False(t, filter.Matches(metadata))
	})

	t.Run("Complex filter - all match", func(t *testing.T) {
		filter := &Filter{
			Authors:       []string{"pdteam"},
			Tags:          []string{"cve"},
			Severities:    []severity.Severity{severity.Critical},
			ProtocolTypes: []types.ProtocolType{types.HTTPProtocol},
		}
		require.True(t, filter.Matches(metadata))
	})

	t.Run("Complex filter - AND logic across types", func(t *testing.T) {
		filter := &Filter{
			Authors:    []string{"pdteam"},                     // matches
			Tags:       []string{"xss"},                        // doesn't match
			Severities: []severity.Severity{severity.Critical}, // matches
		}
		// With AND logic across filter types, doesn't match because tags don't match
		// even though author and severity match
		require.False(t, filter.Matches(metadata))
	})

	t.Run("Complex filter - no match at all", func(t *testing.T) {
		filter := &Filter{
			Authors:    []string{"unknown"},               // doesn't match
			Tags:       []string{"xss"},                   // doesn't match
			Severities: []severity.Severity{severity.Low}, // doesn't match
		}
		require.False(t, filter.Matches(metadata))
	})
}

func TestMatchesPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		pattern  string
		expected bool
	}{
		{"exact match", "/templates/cves/2021/test.yaml", "/templates/cves/2021/test.yaml", true},
		{"directory prefix", "/templates/cves/2021/test.yaml", "/templates/cves", true},
		{"directory with slash", "/templates/cves/2021/test.yaml", "/templates/cves/", true},
		{"no match", "/templates/cves/2021/test.yaml", "/templates/exploits", false},
		{"wildcard match", "/templates/cves/2021/test.yaml", "/templates/*/2021/*.yaml", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesPath(tt.path, tt.pattern)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchesID(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		pattern  string
		expected bool
	}{
		{"exact match", "CVE-2021-1234", "CVE-2021-1234", true},
		{"wildcard prefix", "CVE-2021-1234", "CVE-*", true},
		{"wildcard suffix", "CVE-2021-1234", "*-1234", true},
		{"wildcard middle", "CVE-2021-1234", "CVE-*-1234", true},
		{"no match", "CVE-2021-1234", "CVE-2022-*", false},
		{"partial no match", "CVE-2021-1234", "CVE-2021-12", false},
		{"case insensitive exact", "cve-2021-1234", "CVE-2021-1234", true},
		{"case insensitive wildcard", "CVE-2021-1234", "cve-*", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesID(tt.id, tt.pattern)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestUnmarshalFilter(t *testing.T) {
	filter, err := UnmarshalFilter(
		[]string{"author1", "author2"},
		[]string{"tag1", "tag2"},
		[]string{"exclude-tag"},
		[]string{"include-tag"},
		[]string{"id1", "id2*"},
		[]string{"exclude-id*"},
		[]string{"/include/path"},
		[]string{"/exclude/path"},
		[]string{"critical", "high"},
		[]string{"info"},
		[]string{"http", "dns"},
		[]string{"file"},
	)

	require.NoError(t, err)
	require.NotNil(t, filter)

	require.Equal(t, []string{"author1", "author2"}, filter.Authors)
	require.Equal(t, []string{"tag1", "tag2"}, filter.Tags)
	require.Equal(t, []string{"exclude-tag"}, filter.ExcludeTags)
	require.Equal(t, []string{"include-tag"}, filter.IncludeTags)
	require.Equal(t, []string{"id1", "id2*"}, filter.IDs)
	require.Equal(t, []string{"exclude-id*"}, filter.ExcludeIDs)
	require.Equal(t, []string{"/include/path"}, filter.IncludeTemplates)
	require.Equal(t, []string{"/exclude/path"}, filter.ExcludeTemplates)

	require.Len(t, filter.Severities, 2)
	require.Contains(t, filter.Severities, severity.Critical)
	require.Contains(t, filter.Severities, severity.High)

	require.Len(t, filter.ExcludeSeverities, 1)
	require.Contains(t, filter.ExcludeSeverities, severity.Info)

	require.Len(t, filter.ProtocolTypes, 2)
	require.Contains(t, filter.ProtocolTypes, types.HTTPProtocol)
	require.Contains(t, filter.ProtocolTypes, types.DNSProtocol)

	require.Len(t, filter.ExcludeProtocolTypes, 1)
	require.Contains(t, filter.ExcludeProtocolTypes, types.FileProtocol)
}

func TestIndexFilter(t *testing.T) {
	tmpDir := t.TempDir()
	idx, err := NewIndex(tmpDir)
	require.NoError(t, err)

	// Create test templates and metadata
	templates := []struct {
		id       string
		path     string
		authors  []string
		tags     []string
		severity string
		protocol string
	}{
		{"cve-2021-1", "/templates/cves/CVE-2021-1.yaml", []string{"pdteam"}, []string{"cve", "rce"}, "critical", "http"},
		{"cve-2021-2", "/templates/cves/CVE-2021-2.yaml", []string{"pdteam"}, []string{"cve", "xss"}, "high", "http"},
		{"exploit-1", "/templates/exploits/exploit-1.yaml", []string{"geeknik"}, []string{"exploit"}, "medium", "dns"},
		{"info-1", "/templates/info/info-1.yaml", []string{"author1"}, []string{"info"}, "info", "http"},
	}

	for _, tmpl := range templates {
		tmpFile := filepath.Join(tmpDir, filepath.Base(tmpl.path))
		err := os.WriteFile(tmpFile, []byte("id: "+tmpl.id), 0644)
		require.NoError(t, err)

		metadata := &Metadata{
			ID:           tmpl.id,
			FilePath:     tmpFile,
			Authors:      tmpl.authors,
			Tags:         tmpl.tags,
			Severity:     tmpl.severity,
			ProtocolType: tmpl.protocol,
		}
		idx.Set(tmpl.path, metadata)
	}

	t.Run("No filter returns all", func(t *testing.T) {
		results := idx.Filter(nil)
		require.Len(t, results, 4)
	})

	t.Run("Filter by author", func(t *testing.T) {
		filter := &Filter{Authors: []string{"pdteam"}}
		results := idx.Filter(filter)
		require.Len(t, results, 2)
	})

	t.Run("Filter by tag", func(t *testing.T) {
		filter := &Filter{Tags: []string{"cve"}}
		results := idx.Filter(filter)
		require.Len(t, results, 2)
	})

	t.Run("Filter by severity", func(t *testing.T) {
		filter := &Filter{Severities: []severity.Severity{severity.Critical}}
		results := idx.Filter(filter)
		require.Len(t, results, 1)
	})

	t.Run("Filter by protocol type", func(t *testing.T) {
		filter := &Filter{ProtocolTypes: []types.ProtocolType{types.HTTPProtocol}}
		results := idx.Filter(filter)
		require.Len(t, results, 3)
	})

	t.Run("Exclude by severity", func(t *testing.T) {
		filter := &Filter{ExcludeSeverities: []severity.Severity{severity.Info}}
		results := idx.Filter(filter)
		require.Len(t, results, 3)
	})

	t.Run("Exclude by tag", func(t *testing.T) {
		filter := &Filter{ExcludeTags: []string{"info"}}
		results := idx.Filter(filter)
		require.Len(t, results, 3)
	})

	t.Run("Complex filter", func(t *testing.T) {
		filter := &Filter{
			Tags:              []string{"cve"},
			Severities:        []severity.Severity{severity.Critical, severity.High},
			ExcludeSeverities: []severity.Severity{severity.Info},
		}
		results := idx.Filter(filter)
		require.Len(t, results, 2)
	})

	t.Run("Count with filter", func(t *testing.T) {
		filter := &Filter{Tags: []string{"cve"}}
		count := idx.Count(filter)
		require.Equal(t, 2, count)
	})

	t.Run("Count without filter", func(t *testing.T) {
		count := idx.Count(nil)
		require.Equal(t, 4, count)
	})
}

func TestIndexFilterFunc(t *testing.T) {
	tmpDir := t.TempDir()
	idx, err := NewIndex(tmpDir)
	require.NoError(t, err)

	// Add test metadata
	for i := 0; i < 5; i++ {
		metadata := &Metadata{
			ID:       "test-" + string(rune('a'+i)),
			FilePath: "/tmp/test.yaml",
			Severity: "high",
		}
		if i%2 == 0 {
			metadata.Tags = []string{"even"}
		} else {
			metadata.Tags = []string{"odd"}
		}
		idx.Set("/tmp/test-"+string(rune('a'+i))+".yaml", metadata)
	}

	t.Run("Custom filter function", func(t *testing.T) {
		results := idx.FilterFunc(func(m *Metadata) bool {
			return m.HasTag("even")
		})
		require.Len(t, results, 3) // 0, 2, 4
	})

	t.Run("Nil filter function returns all", func(t *testing.T) {
		results := idx.FilterFunc(nil)
		require.Len(t, results, 5)
	})
}

func TestFilterString(t *testing.T) {
	filter := &Filter{
		Authors:       []string{"author1", "author2"},
		Tags:          []string{"tag1"},
		Severities:    []severity.Severity{severity.Critical, severity.High},
		ProtocolTypes: []types.ProtocolType{types.HTTPProtocol},
	}

	str := filter.String()
	require.Contains(t, str, "authors=")
	require.Contains(t, str, "tags=")
	require.Contains(t, str, "severities=")
	require.Contains(t, str, "types=")

	emptyFilter := &Filter{}
	require.Equal(t, "filter=<nil>", emptyFilter.String())
}
