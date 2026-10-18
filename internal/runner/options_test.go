package runner

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/goflags"
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, readsTargetsFromStdin(tc.options, tc.stdinIsPipe))
		})
	}
}
