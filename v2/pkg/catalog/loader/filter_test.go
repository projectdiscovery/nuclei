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
		matched, _ := filter.match("jira", "pdteam", "low")
		require.True(t, matched, "could not get correct match")
	})
	t.Run("false", func(t *testing.T) {
		matched, _ := filter.match("consul", "pdteam", "low")
		require.False(t, matched, "could not get correct match")
	})
	t.Run("not-match-excludes", func(t *testing.T) {
		config := &Config{
			Tags:        []string{"cves", "dos"},
			ExcludeTags: []string{"dos"},
		}
		filter := config.createTagFilter()
		matched, err := filter.match("dos", "pdteam", "low")
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
		matched, err := filter.match("fuzz", "pdteam", "low")
		require.Nil(t, err, "could not get match")
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-author", func(t *testing.T) {
		config := &Config{
			Authors: []string{"pdteam"},
		}
		filter := config.createTagFilter()
		matched, _ := filter.match("fuzz", "pdteam", "low")
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-severity", func(t *testing.T) {
		config := &Config{
			Severities: []string{"high"},
		}
		filter := config.createTagFilter()
		matched, _ := filter.match("fuzz", "pdteam", "high")
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-conditions", func(t *testing.T) {
		config := &Config{
			Authors:    []string{"pdteam"},
			Tags:       []string{"jira"},
			Severities: []string{"high"},
		}
		filter := config.createTagFilter()
		matched, _ := filter.match("jira", "pdteam", "high")
		require.True(t, matched, "could not get correct match")
		matched, _ = filter.match("jira", "pdteam", "low")
		require.False(t, matched, "could not get correct match")
		matched, _ = filter.match("jira", "random", "low")
		require.False(t, matched, "could not get correct match")
		matched, _ = filter.match("consul", "random", "low")
		require.False(t, matched, "could not get correct match")
	})
}
