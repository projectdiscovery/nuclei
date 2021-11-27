package filter

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
)

func TestTagBasedFilter(t *testing.T) {
	{
		filter := New(&Config{
			Tags: []string{"cves", "2021", "jira"},
		})

		t.Run("true", func(t *testing.T) {
			matched, _ := filter.Match([]string{"jira"}, []string{"pdteam"}, severity.Low, nil, types.HTTPProtocol)
			require.True(t, matched, "could not get correct match")
		})
		t.Run("false", func(t *testing.T) {
			matched, _ := filter.Match([]string{"consul"}, []string{"pdteam"}, severity.Low, nil, types.HTTPProtocol)
			require.False(t, matched, "could not get correct match")
		})
		t.Run("match-extra-tags-positive", func(t *testing.T) {
			matched, _ := filter.Match([]string{"cves", "vuln"}, []string{"pdteam"}, severity.Low, []string{"vuln"}, types.HTTPProtocol)
			require.True(t, matched, "could not get correct match")
		})
		t.Run("match-extra-tags-negative", func(t *testing.T) {
			matched, _ := filter.Match([]string{"cves"}, []string{"pdteam"}, severity.Low, []string{"vuln"}, types.HTTPProtocol)
			require.False(t, matched, "could not get correct match")
		})
	}

	t.Run("not-match-excludes", func(t *testing.T) {
		filter := New(&Config{
			ExcludeTags: []string{"dos"},
		})
		matched, err := filter.Match([]string{"dos"}, []string{"pdteam"}, severity.Low, nil, types.HTTPProtocol)
		require.False(t, matched, "could not get correct match")
		require.Equal(t, ErrExcluded, err, "could not get correct error")
	})
	t.Run("match-includes", func(t *testing.T) {
		filter := New(&Config{
			Tags:        []string{"cves", "fuzz"},
			ExcludeTags: []string{"dos", "fuzz"},
			IncludeTags: []string{"fuzz"},
		})
		matched, err := filter.Match([]string{"fuzz"}, []string{"pdteam"}, severity.Low, nil, types.HTTPProtocol)
		require.Nil(t, err, "could not get match")
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-includes", func(t *testing.T) {
		filter := New(&Config{
			Tags:        []string{"fuzz"},
			ExcludeTags: []string{"fuzz"},
		})
		matched, err := filter.Match([]string{"fuzz"}, []string{"pdteam"}, severity.Low, nil, types.HTTPProtocol)
		require.Nil(t, err, "could not get match")
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-author", func(t *testing.T) {
		filter := New(&Config{
			Authors: []string{"pdteam"},
		})
		matched, _ := filter.Match([]string{"fuzz"}, []string{"pdteam"}, severity.Low, nil, types.HTTPProtocol)
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-severity", func(t *testing.T) {
		filter := New(&Config{
			Severities: severity.Severities{severity.High},
		})
		matched, _ := filter.Match([]string{"fuzz"}, []string{"pdteam"}, severity.High, nil, types.HTTPProtocol)
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-exclude-severity", func(t *testing.T) {
		filter := New(&Config{
			ExcludeSeverities: severity.Severities{severity.Low},
		})
		matched, _ := filter.Match([]string{"fuzz"}, []string{"pdteam"}, severity.High, nil, types.HTTPProtocol)
		require.True(t, matched, "could not get correct match")

		matched, _ = filter.Match([]string{"fuzz"}, []string{"pdteam"}, severity.Low, nil, types.HTTPProtocol)
		require.False(t, matched, "could not get correct match")
	})
	t.Run("match-exclude-with-tags", func(t *testing.T) {
		filter := New(&Config{
			Tags:        []string{"tag"},
			ExcludeTags: []string{"another"},
		})
		matched, _ := filter.Match([]string{"another"}, []string{"pdteam"}, severity.High, nil, types.HTTPProtocol)
		require.False(t, matched, "could not get correct match")
	})
	t.Run("match-conditions", func(t *testing.T) {
		filter := New(&Config{
			Authors:    []string{"pdteam"},
			Tags:       []string{"jira"},
			Severities: severity.Severities{severity.High},
		})
		matched, _ := filter.Match([]string{"jira", "cve"}, []string{"pdteam", "someOtherUser"}, severity.High, nil, types.HTTPProtocol)
		require.True(t, matched, "could not get correct match")

		matched, _ = filter.Match([]string{"jira"}, []string{"pdteam"}, severity.Low, nil, types.HTTPProtocol)
		require.False(t, matched, "could not get correct match")

		matched, _ = filter.Match([]string{"jira"}, []string{"random"}, severity.Low, nil, types.HTTPProtocol)
		require.False(t, matched, "could not get correct match")

		matched, _ = filter.Match([]string{"consul"}, []string{"random"}, severity.Low, nil, types.HTTPProtocol)
		require.False(t, matched, "could not get correct match")
	})
	t.Run("match-type", func(t *testing.T) {
		filter := New(&Config{
			Protocols: []types.ProtocolType{types.HTTPProtocol},
		})
		matched, _ := filter.Match([]string{"fuzz"}, []string{"pdteam"}, severity.High, nil, types.HTTPProtocol)
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-exclude-type", func(t *testing.T) {
		filter := New(&Config{
			ExcludeProtocols: []types.ProtocolType{types.HTTPProtocol},
		})
		matched, _ := filter.Match([]string{"fuzz"}, []string{"pdteam"}, severity.High, nil, types.DNSProtocol)
		require.True(t, matched, "could not get correct match")

		matched, _ = filter.Match([]string{"fuzz"}, []string{"pdteam"}, severity.Low, nil, types.HTTPProtocol)
		require.False(t, matched, "could not get correct match")
	})
}
