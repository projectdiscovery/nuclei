package protocolinit

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestProcessSandboxEnabled(t *testing.T) {
	tests := []struct {
		name    string
		options *types.Options
		want    bool
	}{
		{name: "nil options", options: nil, want: false},
		{name: "sdk default", options: &types.Options{}, want: false},
		{name: "cli default", options: &types.Options{EnableProcessSandbox: true}, want: true},
		{name: "cli no-sandbox", options: &types.Options{EnableProcessSandbox: true, DisableSandbox: true}, want: false},
		{name: "disable without enable", options: &types.Options{DisableSandbox: true}, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ProcessSandboxEnabled(test.options); got != test.want {
				t.Fatalf("ProcessSandboxEnabled() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestProcessSandboxEnabledSurvivesCopy(t *testing.T) {
	options := &types.Options{EnableProcessSandbox: true}
	if !ProcessSandboxEnabled(options.Copy()) {
		t.Fatal("Options.Copy dropped EnableProcessSandbox")
	}
}
