package hybrid

import (
	"testing"

	"github.com/projectdiscovery/hmap/store/hybrid"
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
	}
}

func Test_isCIDR(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{
			name:     "CIDR",
			value:    "173.0.84.0/30",
			expected: true,
		},
		{
			name:     "FQDN",
			value:    "one.one.one.one",
			expected: false,
		},
		{
			name:     "URL",
			value:    "https://one.one.one.one",
			expected: false,
		},
		{
			name:     "IP",
			value:    "173.0.84.0",
			expected: false,
		},
		{
			name:     "CIDR2",
			value:    "104.154.124.0/32",
			expected: true,
		},
		{
			name:     "WrongCIDR",
			value:    "198.154.124.0.0/32",
			expected: false,
		},
	}
	for _, tt := range tests {
		got := isCIDR(tt.value)
		require.Equal(t, tt.expected, got)
	}
}
