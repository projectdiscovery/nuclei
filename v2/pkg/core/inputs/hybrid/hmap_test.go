package hybrid

import (
	"os"
	"strings"
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
		require.ElementsMatch(t, tt.expected, got, "could not get correct cidrs")
	}
}

func Test_expandASNInputValue(t *testing.T) {
	tests := []struct {
		asn                string
		expectedOutputFile string
	}{
		{
			asn:                "AS14421",
			expectedOutputFile: "tests/AS14421.txt",
		},
		{
			asn:                "AS134029",
			expectedOutputFile: "tests/AS134029.txt",
		},
	}
	for _, tt := range tests {
		hm, err := hybrid.New(hybrid.DefaultDiskOptions)
		require.Nil(t, err, "could not create temporary input file")
		input := &Input{hostMap: hm}
		// get the IP addresses for ASN number
		input.expandASNInputValue(tt.asn)
		// scan the hmap
		got := []string{}
		input.hostMap.Scan(func(k, v []byte) error {
			got = append(got, string(k))
			return nil
		})
		// read the expected IPs from the file
		fileContent, err := os.ReadFile(tt.expectedOutputFile)
		require.Nil(t, err, "could not read the expectedOutputFile file")

		items := strings.Split(strings.ReplaceAll(string(fileContent), "\r\n", "\n"), "\n")

		require.ElementsMatch(t, items, got, "could not get correct ips")
	}
}
