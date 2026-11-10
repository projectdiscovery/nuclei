package runner

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestParseHeadlessOptionalArguments(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string]string
	}{
		{
			name:  "single value",
			input: "a=b",
			want:  map[string]string{"a": "b"},
		},
		{
			name:  "empty string",
			input: "",
			want:  map[string]string{},
		},
		{
			name:  "empty key",
			input: "=b",
			want:  map[string]string{},
		},
		{
			name:  "empty value",
			input: "a=",
			want:  map[string]string{},
		},
		{
			name:  "double input",
			input: "a=b,c=d",
			want:  map[string]string{"a": "b", "c": "d"},
		},
		{
			name:  "duplicated input",
			input: "a=b,a=b",
			want:  map[string]string{"a": "b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strsl := goflags.StringSlice{}
			for v := range strings.SplitSeq(tt.input, ",") {
				//nolint
				strsl.Set(v)
			}
			opt := types.Options{HeadlessOptionalArguments: strsl}
			got := opt.ParseHeadlessOptionalArguments()
			require.Equal(t, tt.want, got)
		})
	}
}

// TestValidateOptionsUpdateTemplatesChannel checks that only known templates
// update channels are accepted.
func TestValidateOptionsUpdateTemplatesChannel(t *testing.T) {
	for _, channel := range []string{"", installer.TemplatesChannelStable, installer.TemplatesChannelLatest} {
		require.NoError(t, ValidateOptions(&types.Options{UpdateTemplatesChannel: channel}), "channel %q", channel)
	}
	require.ErrorContains(t, ValidateOptions(&types.Options{UpdateTemplatesChannel: "nightly"}), `invalid templates update channel "nightly"`)
}

func TestReadsTargetsFromStdin(t *testing.T) {
	for _, tc := range []struct {
		name        string
		options     *types.Options
		stdinIsPipe bool
		want        bool
	}{
		{"piped stdin alone", &types.Options{}, true, true},
		{"no pipe", &types.Options{}, false, false},
		{"disabled", &types.Options{DisableStdin: true}, true, false},
		{"targets given with -u", &types.Options{Targets: goflags.StringSlice{"example.com"}}, true, false},
		{"targets given with -l", &types.Options{TargetsFilePath: "targets.txt"}, true, false},
		{"uncover query", &types.Options{UncoverQuery: goflags.StringSlice{"example"}}, true, false},
		{"uncover enabled", &types.Options{Uncover: true}, true, false},
		{"replay", &types.Options{ReplayFile: "events.jsonl"}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, readsTargetsFromStdin(tc.options, tc.stdinIsPipe))
		})
	}
}

// The default must remain empty so the provider can distinguish automatic
// IPv6 preference from explicit user-supplied -iv selections.
func TestValidateOptionsIPVersionPreference(t *testing.T) {
	automatic := &types.Options{}
	require.NoError(t, ValidateOptions(automatic))
	require.Empty(t, automatic.IPVersion)
	for _, versions := range []goflags.StringSlice{{"4"}, {"6"}, {"4", "6"}} {
		require.NoError(t, ValidateOptions(&types.Options{IPVersion: versions}))
	}
	require.ErrorContains(t, ValidateOptions(&types.Options{IPVersion: goflags.StringSlice{"7"}}), "unsupported ip version")
}
