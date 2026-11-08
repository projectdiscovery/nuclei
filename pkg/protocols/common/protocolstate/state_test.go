package protocolstate

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestExcludeTargetsMatchExactHost(t *testing.T) {
	opts := types.DefaultOptions()
	opts.ExecutionId = "test-exclude-targets"
	opts.ExcludeTargets = []string{"test.com", "192.0.2.0/24", `^regex\.example$`, "bücher.example"}
	require.NoError(t, Init(opts))
	defer Close(opts.ExecutionId)

	np := GetDialersWithId(opts.ExecutionId).NetworkPolicy
	require.False(t, np.Validate("test.com"))
	require.False(t, np.Validate("TEST.com"))
	require.False(t, np.Validate("test.com."))
	require.False(t, np.Validate("sub.test.com"))
	require.False(t, np.Validate("192.0.2.10"))
	require.False(t, np.Validate("regex.example"))
	require.False(t, np.Validate("xn--bcher-kva.example"))
	require.True(t, np.Validate("latest.com"))
	require.True(t, np.Validate("test.com.example.org"))
	require.True(t, np.Validate("testXcom"))
	require.True(t, np.Validate("sub.regex.example"))
}

func TestMappedFormsDeniedByDialer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	require.NoError(t, err)

	for name, set := range map[string]func(*types.Options){
		"lna":           func(o *types.Options) { o.RestrictLocalNetworkAccess = true },
		"exclude-hosts": func(o *types.Options) { o.ExcludeTargets = []string{"127.0.0.1"} },
		"exclude-cidr":  func(o *types.Options) { o.ExcludeTargets = []string{"127.0.0.0/8"} },
	} {
		t.Run(name, func(t *testing.T) {
			opts := types.DefaultOptions()
			opts.ExecutionId = "test-mapped-" + name
			set(opts)
			require.NoError(t, Init(opts))
			defer Close(opts.ExecutionId)

			d := GetDialersWithId(opts.ExecutionId)
			hosts := []string{"127.0.0.1", "::ffff:127.0.0.1", "::ffff:7f00:1", "0:0:0:0:0:ffff:127.0.0.1"}
			if opts.RestrictLocalNetworkAccess {
				hosts = append(hosts, "::")
			}
			for _, host := range hosts {
				require.False(t, d.NetworkPolicy.Validate(host), host)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				conn, err := d.Fastdialer.Dial(ctx, "tcp", net.JoinHostPort(host, port))
				cancel()
				if conn != nil {
					_ = conn.Close()
				}
				require.Error(t, err, host)
			}
			require.True(t, d.NetworkPolicy.Validate("::ffff:8.8.8.8"))
			require.True(t, d.NetworkPolicy.Validate("8.8.8.8"))
		})
	}
}

func TestMappedDenyRanges(t *testing.T) {
	require.Equal(t, []string{"::ffff:127.0.0.0/104", "::ffff:192.0.2.10/128", "::ffff:0.0.0.0/104"},
		mappedDenyRanges([]string{"127.0.0.0/8", "192.0.2.10", "::1/128", "fc00::/7", `(?i)(^|\.)test\.com\.?$`, "0.0.0.0/8"}))
}
