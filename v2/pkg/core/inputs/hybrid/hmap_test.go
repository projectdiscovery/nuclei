package hybrid

import (
	"testing"

	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/stretchr/testify/require"
)

func Test_expandCIDRInputValue(t *testing.T) {
	tests := []struct {
		cidr     string
		expected []string
	}{
		{
			cidr:     "173.0.84.0/30",
			expected: []string{"173.0.84.0", "173.0.84.1", "173.0.84.2", "173.0.84.3"},
		}, {
			cidr:     "104.154.124.0/29",
			expected: []string{"104.154.124.0", "104.154.124.1", "104.154.124.2", "104.154.124.3", "104.154.124.4", "104.154.124.5", "104.154.124.6", "104.154.124.7"},
		},
	}
	for _, tt := range tests {
		hm, err := hybrid.New(hybrid.DefaultDiskOptions)
		require.Nil(t, err, "could not create temporary input file")
		input := &Input{hostMap: hm}

		input.expandCIDRInputValue(tt.cidr)
		// scan
		got := []string{}
		input.hostMap.Scan(func(k, v []byte) error {
			got = append(got, string(k))
			return nil
		})
		require.ElementsMatch(t, tt.expected, got, "could not get correct ips")
		input.Close()
	}
}

func Test_scanallips_normalizeStoreInputValue(t *testing.T) {
	defaultOpts := types.DefaultOptions()
	_ = protocolstate.Init(defaultOpts)
	tests := []struct {
		hostname string
		ipv4     bool
		ipv6     bool
		expected []string
	}{
		{
			hostname: "scanme.sh",
			ipv4:     true,
			ipv6:     true,
			expected: []string{"128.199.158.128", "2400:6180:0:d0::91:1001"},
		}, {
			hostname: "scanme.sh",
			ipv4:     true,
			expected: []string{"128.199.158.128"},
		}, {
			hostname: "scanme.sh",
			ipv6:     true,
			expected: []string{"2400:6180:0:d0::91:1001"},
		}, {
			hostname: "http://scanme.sh",
			ipv4:     true,
			ipv6:     true,
			expected: []string{"http://128.199.158.128", "http://[2400:6180:0:d0::91:1001]"},
		},
	}
	for _, tt := range tests {
		hm, err := hybrid.New(hybrid.DefaultDiskOptions)
		require.Nil(t, err, "could not create temporary input file")
		input := &Input{
			hostMap: hm,
			ipOptions: &ipOptions{
				ScanAllIPs: true,
				IPV4:       tt.ipv4,
				IPV6:       tt.ipv6,
			},
		}

		input.normalizeStoreInputValue(tt.hostname)
		// scan
		got := []string{}
		input.hostMap.Scan(func(k, v []byte) error {
			got = append(got, string(k))
			return nil
		})
		require.ElementsMatch(t, tt.expected, got, "could not get correct ips")
		input.Close()
	}
}
