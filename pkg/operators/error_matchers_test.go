package operators

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/stretchr/testify/require"
)

func TestHasErrorMatchers(t *testing.T) {
	t.Run("error type", func(t *testing.T) {
		ops := &Operators{Matchers: []*matchers.Matcher{{
			Type:   matchers.MatcherTypeHolder{MatcherType: matchers.ErrorMatcher},
			Errors: []string{"timeout"},
		}}}
		require.NoError(t, ops.Compile())
		require.True(t, ops.HasErrorMatchers())
	})

	t.Run("dsl timeout var", func(t *testing.T) {
		ops := &Operators{Matchers: []*matchers.Matcher{{
			Type: matchers.MatcherTypeHolder{MatcherType: matchers.DSLMatcher},
			DSL:  []string{"timeout == true"},
		}}}
		require.NoError(t, ops.Compile())
		require.True(t, ops.HasErrorMatchers())
	})

	t.Run("dsl error_type var", func(t *testing.T) {
		ops := &Operators{Matchers: []*matchers.Matcher{{
			Type: matchers.MatcherTypeHolder{MatcherType: matchers.DSLMatcher},
			DSL:  []string{`error_type == "timeout"`},
		}}}
		require.NoError(t, ops.Compile())
		require.True(t, ops.HasErrorMatchers())
	})

	t.Run("dsl error var", func(t *testing.T) {
		ops := &Operators{Matchers: []*matchers.Matcher{{
			Type: matchers.MatcherTypeHolder{MatcherType: matchers.DSLMatcher},
			DSL:  []string{`contains(error, "refused")`},
		}}}
		require.NoError(t, ops.Compile())
		require.True(t, ops.HasErrorMatchers())
	})

	t.Run("dsl without error vars", func(t *testing.T) {
		ops := &Operators{Matchers: []*matchers.Matcher{{
			Type: matchers.MatcherTypeHolder{MatcherType: matchers.DSLMatcher},
			DSL:  []string{"status_code == 200"},
		}}}
		require.NoError(t, ops.Compile())
		require.False(t, ops.HasErrorMatchers())
	})

	t.Run("dsl timeout as identifier prefix does not match", func(t *testing.T) {
		ops := &Operators{Matchers: []*matchers.Matcher{{
			Type: matchers.MatcherTypeHolder{MatcherType: matchers.DSLMatcher},
			DSL:  []string{"timeout_ms > 100"},
		}}}
		require.NoError(t, ops.Compile())
		require.False(t, ops.HasErrorMatchers())
	})

	t.Run("word matcher only", func(t *testing.T) {
		ops := &Operators{Matchers: []*matchers.Matcher{{
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words: []string{"ok"},
			Part:  "body",
		}}}
		require.NoError(t, ops.Compile())
		require.False(t, ops.HasErrorMatchers())
	})

	t.Run("nil operators", func(t *testing.T) {
		var ops *Operators
		require.False(t, ops.HasErrorMatchers())
	})
}
