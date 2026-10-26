package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAddCookieIgnore(t *testing.T) {
	exact := map[string]struct{}{}
	prefixes := map[string]struct{}{}
	for _, name := range []string{"_ga", " _gid ", "_ga_*", "(?i)ltpatoken", "_circle_session:", "a*b", "*", ""} {
		addCookieIgnore(exact, prefixes, name)
	}
	require.Equal(t, []string{"_ga", "_gid"}, sortedKeys(exact))
	require.Equal(t, []string{"_ga_"}, sortedKeys(prefixes))
}
