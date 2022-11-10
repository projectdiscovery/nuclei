package fuzz

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRuleMatchKeyOrValue(t *testing.T) {
	rule := &Rule{}
	err := rule.Compile(nil, nil)
	require.NoError(t, err, "could not compile rule")

	result := rule.matchKeyOrValue("url", "")
	require.True(t, result, "could not get correct result")

	t.Run("key", func(t *testing.T) {
		rule := &Rule{Keys: []string{"url"}}
		err := rule.Compile(nil, nil)
		require.NoError(t, err, "could not compile rule")

		result := rule.matchKeyOrValue("url", "")
		require.True(t, result, "could not get correct result")
		result = rule.matchKeyOrValue("test", "")
		require.False(t, result, "could not get correct result")
	})
	t.Run("value", func(t *testing.T) {
		rule := &Rule{ValuesRegex: []string{`https?:\/\/?([-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b)*(\/[\/\d\w\.-]*)*(?:[\?])*(.+)*`}}
		err := rule.Compile(nil, nil)
		require.NoError(t, err, "could not compile rule")

		result := rule.matchKeyOrValue("", "http://localhost:80")
		require.True(t, result, "could not get correct result")
		result = rule.matchKeyOrValue("test", "random")
		require.False(t, result, "could not get correct result")
	})
}
