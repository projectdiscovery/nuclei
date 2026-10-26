package runner

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestPinnedTargetConflict(t *testing.T) {
	tests := []struct {
		name    string
		options *types.Options
		wantErr bool
	}{
		{name: "no conflicting option", options: &types.Options{}},
		{name: "automatic scan", options: &types.Options{AutomaticScan: true}, wantErr: true},
		{name: "http proxy", options: &types.Options{AliveHttpProxy: "http://127.0.0.1:8080"}, wantErr: true},
		{name: "socks proxy", options: &types.Options{AliveSocksProxy: "socks5://127.0.0.1:1080"}, wantErr: true},
		{name: "replay proxy", options: &types.Options{ReplayProxy: "http://127.0.0.1:8080"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.wantErr, pinnedTargetConflict(tt.options) != nil)
		})
	}
}
