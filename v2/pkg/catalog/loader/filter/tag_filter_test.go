package filter

import (
	"github.com/projectdiscovery/goflags"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTagBasedFilter(t *testing.T) {
	config := &Config{
		Tags: []string{"cves", "2021", "jira"},
	}
	filter := New(config)

	t.Run("true", func(t *testing.T) {
		matched, _ := filter.Match([]string{"jira"}, []string{"pdteam"}, goflags.Low)
		require.True(t, matched, "could not get correct match")
	})
	t.Run("false", func(t *testing.T) {
		matched, _ := filter.Match([]string{"consul"}, []string{"pdteam"}, goflags.Low)
		require.False(t, matched, "could not get correct match")
	})
	t.Run("not-match-excludes", func(t *testing.T) {
		config := &Config{
			ExcludeTags: []string{"dos"},
		}
		filter := New(config)
		matched, err := filter.Match([]string{"dos"}, []string{"pdteam"}, goflags.Low)
		require.False(t, matched, "could not get correct match")
		require.Equal(t, ErrExcluded, err, "could not get correct error")
	})
	t.Run("match-includes", func(t *testing.T) {
		config := &Config{
			Tags:        []string{"cves", "fuzz"},
			ExcludeTags: []string{"dos", "fuzz"},
			IncludeTags: []string{"fuzz"},
		}
		filter := New(config)
		matched, err := filter.Match([]string{"fuzz"}, []string{"pdteam"}, goflags.Low)
		require.Nil(t, err, "could not get match")
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-includes", func(t *testing.T) {
		config := &Config{
			Tags:        []string{"fuzz"},
			ExcludeTags: []string{"fuzz"},
		}
		filter := New(config)
		matched, err := filter.Match([]string{"fuzz"}, []string{"pdteam"}, goflags.Low)
		require.Nil(t, err, "could not get match")
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-author", func(t *testing.T) {
		config := &Config{
			Authors: []string{"pdteam"},
		}
		filter := New(config)
		matched, _ := filter.Match([]string{"fuzz"}, []string{"pdteam"}, goflags.Low)
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-severity", func(t *testing.T) {
		config := &Config{
			Severities: goflags.Severities{goflags.High},
		}
		filter := New(config)
		matched, _ := filter.Match([]string{"fuzz"}, []string{"pdteam"}, goflags.High)
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-conditions", func(t *testing.T) {
		config := &Config{
			Authors:    []string{"pdteam"},
			Tags:       []string{"jira"},
			Severities: goflags.Severities{goflags.High},
		}
		filter := New(config)
		matched, _ := filter.Match([]string{"jira"}, []string{"pdteam"}, goflags.High)
		require.True(t, matched, "could not get correct match")
		matched, _ = filter.Match([]string{"jira"}, []string{"pdteam"}, goflags.Low)
		require.False(t, matched, "could not get correct match")
		matched, _ = filter.Match([]string{"jira"}, []string{"random"}, goflags.Low)
		require.False(t, matched, "could not get correct match")
		matched, _ = filter.Match([]string{"consul"}, []string{"random"}, goflags.Low)
		require.False(t, matched, "could not get correct match")
	})
}
