package matchers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatchError(t *testing.T) {
	t.Run("any error when errors empty", func(t *testing.T) {
		m := &Matcher{Type: MatcherTypeHolder{MatcherType: ErrorMatcher}}
		require.NoError(t, m.CompileMatchers())
		ok, snippets := m.MatchError(map[string]interface{}{"error": "boom", "error_type": "unknown", "timeout": false})
		require.True(t, m.Result(ok))
		require.Equal(t, []string{"boom"}, snippets)
		ok, _ = m.MatchError(map[string]interface{}{})
		require.False(t, m.Result(ok))
	})

	t.Run("empty error string does not match", func(t *testing.T) {
		m := &Matcher{Type: MatcherTypeHolder{MatcherType: ErrorMatcher}, Errors: []string{"any"}}
		require.NoError(t, m.CompileMatchers())
		ok, _ := m.MatchError(map[string]interface{}{"error": "", "error_type": "unknown", "timeout": false})
		require.False(t, m.Result(ok))
		ok, _ = m.MatchError(map[string]interface{}{"error": nil})
		require.False(t, m.Result(ok))
	})

	t.Run("timeout kind", func(t *testing.T) {
		m := &Matcher{Type: MatcherTypeHolder{MatcherType: ErrorMatcher}, Errors: []string{"timeout"}}
		require.NoError(t, m.CompileMatchers())
		ok, _ := m.MatchError(map[string]interface{}{"error": "i/o timeout", "error_type": "timeout", "timeout": true})
		require.True(t, m.Result(ok))
		ok, _ = m.MatchError(map[string]interface{}{"error": "connection refused", "error_type": "connection", "timeout": false})
		require.False(t, m.Result(ok))
	})

	t.Run("connection and connect kinds", func(t *testing.T) {
		for _, kind := range []string{"connection", "connect"} {
			m := &Matcher{Type: MatcherTypeHolder{MatcherType: ErrorMatcher}, Errors: []string{kind}}
			require.NoError(t, m.CompileMatchers())
			ok, _ := m.MatchError(map[string]interface{}{"error": "connection refused", "error_type": "connection", "timeout": false})
			require.True(t, m.Result(ok), "kind %q", kind)
			ok, _ = m.MatchError(map[string]interface{}{"error": "i/o timeout", "error_type": "timeout", "timeout": true})
			require.False(t, m.Result(ok), "kind %q", kind)
		}
	})

	t.Run("any and star kinds", func(t *testing.T) {
		for _, kind := range []string{"any", "*"} {
			m := &Matcher{Type: MatcherTypeHolder{MatcherType: ErrorMatcher}, Errors: []string{kind}}
			require.NoError(t, m.CompileMatchers())
			ok, snippets := m.MatchError(map[string]interface{}{"error": "something went wrong", "error_type": "unknown", "timeout": false})
			require.True(t, m.Result(ok), "kind %q", kind)
			require.Equal(t, []string{"something went wrong"}, snippets)
		}
	})

	t.Run("substring in error message", func(t *testing.T) {
		m := &Matcher{Type: MatcherTypeHolder{MatcherType: ErrorMatcher}, Errors: []string{"connection refused"}}
		require.NoError(t, m.CompileMatchers())
		ok, snippets := m.MatchError(map[string]interface{}{"error": "dial tcp 127.0.0.1:1: connection refused", "error_type": "connection", "timeout": false})
		require.True(t, m.Result(ok))
		require.Equal(t, []string{"connection refused"}, snippets)

		ok, _ = m.MatchError(map[string]interface{}{"error": "i/o timeout", "error_type": "timeout", "timeout": true})
		require.False(t, m.Result(ok))
	})

	t.Run("case insensitive substring", func(t *testing.T) {
		m := &Matcher{
			Type:            MatcherTypeHolder{MatcherType: ErrorMatcher},
			Errors:          []string{"No Such Host"},
			CaseInsensitive: true,
		}
		require.NoError(t, m.CompileMatchers())
		ok, snippets := m.MatchError(map[string]interface{}{"error": "lookup example.invalid: no such host", "error_type": "connection", "timeout": false})
		require.True(t, m.Result(ok))
		require.Equal(t, []string{"No Such Host"}, snippets)
	})

	t.Run("case sensitive substring misses", func(t *testing.T) {
		m := &Matcher{
			Type:   MatcherTypeHolder{MatcherType: ErrorMatcher},
			Errors: []string{"No Such Host"},
		}
		require.NoError(t, m.CompileMatchers())
		ok, _ := m.MatchError(map[string]interface{}{"error": "lookup example.invalid: no such host", "error_type": "connection", "timeout": false})
		require.False(t, m.Result(ok))
	})

	t.Run("or condition across kind and substring", func(t *testing.T) {
		m := &Matcher{
			Type:      MatcherTypeHolder{MatcherType: ErrorMatcher},
			Errors:    []string{"timeout", "no such host"},
			Condition: "or",
		}
		require.NoError(t, m.CompileMatchers())
		ok, _ := m.MatchError(map[string]interface{}{"error": "lookup x: no such host", "error_type": "connection", "timeout": false})
		require.True(t, m.Result(ok))
		ok, _ = m.MatchError(map[string]interface{}{"error": "i/o timeout", "error_type": "timeout", "timeout": true})
		require.True(t, m.Result(ok))
		ok, _ = m.MatchError(map[string]interface{}{"error": "broken pipe", "error_type": "connection", "timeout": false})
		require.False(t, m.Result(ok))
	})

	t.Run("and condition requires all", func(t *testing.T) {
		m := &Matcher{
			Type:      MatcherTypeHolder{MatcherType: ErrorMatcher},
			Errors:    []string{"dial tcp", "connection refused"},
			Condition: "and",
		}
		require.NoError(t, m.CompileMatchers())
		ok, snippets := m.MatchError(map[string]interface{}{"error": "dial tcp 127.0.0.1:1: connection refused", "error_type": "connection", "timeout": false})
		require.True(t, m.Result(ok))
		require.Equal(t, []string{"dial tcp", "connection refused"}, snippets)

		ok, _ = m.MatchError(map[string]interface{}{"error": "dial tcp: i/o timeout", "error_type": "timeout", "timeout": true})
		require.False(t, m.Result(ok))
	})

	t.Run("match-all returns every matching snippet", func(t *testing.T) {
		m := &Matcher{
			Type:      MatcherTypeHolder{MatcherType: ErrorMatcher},
			Errors:    []string{"dial tcp", "connection refused", "missing"},
			Condition: "or",
			MatchAll:  true,
		}
		require.NoError(t, m.CompileMatchers())
		ok, snippets := m.MatchError(map[string]interface{}{"error": "dial tcp 127.0.0.1:1: connection refused", "error_type": "connection", "timeout": false})
		require.True(t, m.Result(ok))
		require.Equal(t, []string{"dial tcp", "connection refused"}, snippets)
	})

	t.Run("negative", func(t *testing.T) {
		m := &Matcher{Type: MatcherTypeHolder{MatcherType: ErrorMatcher}, Errors: []string{"timeout"}, Negative: true}
		require.NoError(t, m.CompileMatchers())
		ok, snippets := m.MatchError(map[string]interface{}{"error": "i/o timeout", "error_type": "timeout", "timeout": true})
		matched, out := m.ResultWithMatchedSnippet(ok, snippets)
		require.False(t, matched)
		require.Empty(t, out)
		ok, _ = m.MatchError(map[string]interface{}{})
		require.True(t, m.Result(ok))
	})
}

func TestHasErrorMatchersViaOperatorsPackage(t *testing.T) {
	m := &Matcher{Type: MatcherTypeHolder{MatcherType: ErrorMatcher}, Errors: []string{"timeout"}}
	require.NoError(t, m.CompileMatchers())
	require.Equal(t, ErrorMatcher, m.GetType())
	require.False(t, m.NeedsPart())
}
