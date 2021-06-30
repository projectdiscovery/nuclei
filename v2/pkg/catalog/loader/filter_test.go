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
		require.True(t, filter.match("jira", "pdteam", "low", false), "could not get correct match")
	})
	t.Run("false", func(t *testing.T) {
		require.False(t, filter.match("consul", "pdteam", "low", false), "could not get correct match")
	})
	t.Run("not-match-excludes", func(t *testing.T) {
		config := &Config{
			Tags:        []string{"cves", "dos"},
			ExcludeTags: []string{"dos"},
		}
		filter := config.createTagFilter()
		require.False(t, filter.match("jira", "pdteam", "low", false), "could not get correct match")
	})
	t.Run("match-includes", func(t *testing.T) {
		config := &Config{
			Tags:        []string{"cves", "fuzz"},
			ExcludeTags: []string{"dos", "fuzz"},
			IncludeTags: []string{"fuzz"},
		}

		filter := config.createTagFilter()
		require.False(t, filter.match("fuzz", "pdteam", "low", false), "could not get correct match")
	})
	t.Run("match-author", func(t *testing.T) {
		config := &Config{
			Authors: []string{"pdteam"},
		}
		filter := config.createTagFilter()
		require.True(t, filter.match("fuzz", "pdteam", "low", false), "could not get correct match")
	})
	t.Run("match-severity", func(t *testing.T) {
		config := &Config{
			Severities: []string{"high"},
		}
		filter := config.createTagFilter()
		require.True(t, filter.match("fuzz", "pdteam", "high", false), "could not get correct match")
	})
	t.Run("match-conditions", func(t *testing.T) {
		config := &Config{
			Authors:    []string{"pdteam"},
			Tags:       []string{"jira"},
			Severities: []string{"high"},
		}
		filter := config.createTagFilter()
		require.True(t, filter.match("jira", "pdteam", "high", false), "could not get correct match")
		require.False(t, filter.match("jira", "pdteam", "low", false), "could not get correct match")
		require.False(t, filter.match("jira", "random", "low", false), "could not get correct match")
		require.False(t, filter.match("consul", "random", "low", false), "could not get correct match")
	})
}
