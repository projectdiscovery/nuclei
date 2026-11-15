package userAgent

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// every named UserAgent value (i.e. every key in userAgentMappings) is a valid
// user_agent option. Random is the zero value and is the default for headless
// requests, so it must be offered alongside the others.
var allNamedUserAgents = []UserAgent{Random, Off, Default, Custom}

func TestGetSupportedUserAgentOptions(t *testing.T) {
	got := GetSupportedUserAgentOptions()

	for _, option := range allNamedUserAgents {
		t.Run(option.String(), func(t *testing.T) {
			require.Contains(t, got, option, "named user-agent option %q must be returned", option)
		})
	}

	require.Len(t, got, len(userAgentMappings), "exactly the named options must be returned")
	require.NotContains(t, got, limit, "the limit sentinel must not be exposed as an option")
}

func TestUserAgentHolderJSONSchemaEnum(t *testing.T) {
	schema := (UserAgentHolder{}).JSONSchema()

	got := make([]string, 0, len(schema.Enum))
	for _, value := range schema.Enum {
		got = append(got, fmt.Sprint(value))
	}

	want := make([]string, 0, len(userAgentMappings))
	for _, name := range userAgentMappings {
		want = append(want, name)
	}

	require.ElementsMatch(t, want, got, "schema enum must list every named user-agent option")
}

func TestUserAgentHolderUnmarshalYAMLRandom(t *testing.T) {
	var holder UserAgentHolder
	require.NoError(t, holder.UnmarshalYAML(func(v interface{}) error {
		*(v.(*string)) = "random"
		return nil
	}))
	require.Equal(t, Random, holder.Value, `"random" must remain a valid user_agent value`)
}
