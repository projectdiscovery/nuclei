package loader

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTagBasedFilter(t *testing.T) {
	config := &Config{
		Tags: []string{"cves", "2021", "jira"},
	}
	filter := config.createTagFilter()

	t.Run("true", func(t *testing.T) {
		matched, _ := filter.match("jira", "pdteam", "low", false)
		require.True(t, matched, "could not get correct match")
	})
	t.Run("false", func(t *testing.T) {
		matched, _ := filter.match("consul", "pdteam", "low", false)
		require.False(t, matched, "could not get correct match")
	})
	t.Run("not-match-excludes", func(t *testing.T) {
		config := &Config{
			Tags:        []string{"cves", "dos"},
			ExcludeTags: []string{"dos"},
		}
		filter := config.createTagFilter()
		matched, err := filter.match("dos", "pdteam", "low", false)
		require.False(t, matched, "could not get correct match")
		require.Equal(t, ErrExcluded, err, "could not get correct error")
	})
	t.Run("match-includes", func(t *testing.T) {
		config := &Config{
			Tags:        []string{"cves", "fuzz"},
			ExcludeTags: []string{"dos", "fuzz"},
			IncludeTags: []string{"fuzz"},
		}

		filter := config.createTagFilter()
		matched, _ := filter.match("fuzz", "pdteam", "low", false)
		require.False(t, matched, "could not get correct match")
	})
	t.Run("match-author", func(t *testing.T) {
		config := &Config{
			Authors: []string{"pdteam"},
		}
		filter := config.createTagFilter()
		matched, _ := filter.match("fuzz", "pdteam", "low", false)
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-severity", func(t *testing.T) {
		config := &Config{
			Severities: []string{"high"},
		}
		filter := config.createTagFilter()
		matched, _ := filter.match("fuzz", "pdteam", "high", false)
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-conditions", func(t *testing.T) {
		config := &Config{
			Authors:    []string{"pdteam"},
			Tags:       []string{"jira"},
			Severities: []string{"high"},
		}
		filter := config.createTagFilter()
		matched, _ := filter.match("jira", "pdteam", "high", false)
		require.True(t, matched, "could not get correct match")
		matched, _ = filter.match("jira", "pdteam", "low", false)
		require.False(t, matched, "could not get correct match")
		matched, _ = filter.match("jira", "random", "low", false)
		require.False(t, matched, "could not get correct match")
		matched, _ = filter.match("consul", "random", "low", false)
		require.False(t, matched, "could not get correct match")
	})
}
