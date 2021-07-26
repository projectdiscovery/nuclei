package filter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTagBasedFilter(t *testing.T) {
	config := &Config{
		Tags: []string{"cves", "2021", "jira"},
	}
	filter := New(config)

	t.Run("true", func(t *testing.T) {
		matched, _ := filter.Match("jira", "pdteam", "low")
		require.True(t, matched, "could not get correct match")
	})
	t.Run("false", func(t *testing.T) {
		matched, _ := filter.Match("consul", "pdteam", "low")
		require.False(t, matched, "could not get correct match")
	})
	t.Run("not-match-excludes", func(t *testing.T) {
		config := &Config{
			ExcludeTags: []string{"dos"},
		}
		filter := New(config)
		matched, err := filter.Match("dos", "pdteam", "low")
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
		matched, err := filter.Match("fuzz", "pdteam", "low")
		require.Nil(t, err, "could not get match")
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-author", func(t *testing.T) {
		config := &Config{
			Authors: []string{"pdteam"},
		}
		filter := New(config)
		matched, _ := filter.Match("fuzz", "pdteam", "low")
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-severity", func(t *testing.T) {
		config := &Config{
			Severities: []string{"high"},
		}
		filter := New(config)
		matched, _ := filter.Match("fuzz", "pdteam", "high")
		require.True(t, matched, "could not get correct match")
	})
	t.Run("match-exclude-with-tags", func(t *testing.T) {
		config := &Config{
			Tags:        []string{"tag"},
			ExcludeTags: []string{"another"},
		}
		filter := New(config)
		matched, _ := filter.Match("another", "pdteam", "high")
		require.False(t, matched, "could not get correct match")
	})
	t.Run("match-conditions", func(t *testing.T) {
		config := &Config{
			Authors:    []string{"pdteam"},
			Tags:       []string{"jira"},
			Severities: []string{"high"},
		}
		filter := New(config)
		matched, _ := filter.Match("jira", "pdteam", "high")
		require.True(t, matched, "could not get correct match")
		matched, _ = filter.Match("jira", "pdteam", "low")
		require.False(t, matched, "could not get correct match")
		matched, _ = filter.Match("jira", "random", "low")
		require.False(t, matched, "could not get correct match")
		matched, _ = filter.Match("consul", "random", "low")
		require.False(t, matched, "could not get correct match")
	})
}
