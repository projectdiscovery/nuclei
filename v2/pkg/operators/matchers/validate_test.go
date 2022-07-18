package matchers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	m := &Matcher{matcherType: DSLMatcher, DSL: []string{"anything"}}

	err := m.Validate()
	require.Nil(t, err, "Could not validate correct template")

	m = &Matcher{matcherType: DSLMatcher, Part: "test"}
	err = m.Validate()
	require.NotNil(t, err, "Invalid template was correctly validated")
}
