package randomip

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetRandomIp(t *testing.T) {
	tests := []struct {
		name     string
		cidr     []string
		errorMsg string
		valid    bool
	}{
		{
			name:  "Valid C class",
			cidr:  []string{"193.6.32.110/24"},
			valid: true,
		},
		{
			name:  "Valid B class",
			cidr:  []string{"128.34.33.29/16"},
			valid: true,
		},
		{
			name:  "Valid A class",
			cidr:  []string{"10.1.2.3/8"},
			valid: true,
		},
		{
			name:  "Valid classless zero based network",
			cidr:  []string{"205.102.139.2/30"},
			valid: true,
		},
		{
			name:  "Valid classless non-zero based network",
			cidr:  []string{"205.102.139.49/29"},
			valid: true,
		},
		{
			name:  "Multiple CIDRs",
			cidr:  []string{"1.2.3.4/15", "230.149.150.22/28"},
			valid: true,
		},
		{
			name:     "Negative CIDR length",
			cidr:     []string{"10.11.12.13/-1"},
			valid:    false,
			errorMsg: "10.11.12.13/-1 is not a valid CIDR",
		},
		{
			name:     "Large CIDR length",
			cidr:     []string{"10.11.12.13/33"},
			valid:    false,
			errorMsg: "10.11.12.13/33 is not a valid CIDR",
		},
		{
			name:     "No CIDR provided",
			cidr:     []string{},
			valid:    false,
			errorMsg: "must specify at least one cidr",
		},
		{
			name:  "Valid but crazy",
			cidr:  []string{"0.0.0.0/0"},
			valid: true,
		},
		{
			name:  "Valid but unlikely",
			cidr:  []string{"193.6.32.109/32"},
			valid: true,
		},
		{
			name:  "Valid IPv6",
			cidr:  []string{"2607:fb91:1294:85fa:3cbf:491:cd46:2625/120"},
			valid: true,
		},
		{
			name:  "Classless IPv4 starting with a non-zero base",
			cidr:  []string{"129.47.78.253/30"},
			valid: true,
		},
		{
			name:  "IPv6 and IPv4",
			cidr:  []string{"2603:8080:4400:d070:913:dee4:6c0c:9ae8/96", "212.78.146.240/25"},
			valid: true,
		},
		{
			name:     "Negative CIDR length IPv6",
			cidr:     []string{"2600:1700:27c:70:44eb:2d78:86b3:e905/-1"},
			valid:    false,
			errorMsg: "2600:1700:27c:70:44eb:2d78:86b3:e905/-1 is not a valid CIDR",
		},
		{
			name:     "Large CIDR length IPv6",
			cidr:     []string{"2607:fb91:bd02:127c:d736:abcf:5c77:e7fd/129"},
			valid:    false,
			errorMsg: "2607:fb91:bd02:127c:d736:abcf:5c77:e7fd/129 is not a valid CIDR",
		},
		{
			name:  "Valid but unlikely IPv6",
			cidr:  []string{"2607:fb91:bd02:127c:d736:abcf:5c77:e7fd/128"},
			valid: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ip, err := GetRandomIPWithCidr(test.cidr...)
			if test.valid {
				assert.NoError(t, err)
				anyInRange := false
				for _, cidr := range test.cidr {
					_, network, _ := net.ParseCIDR(cidr)
					anyInRange = anyInRange || network.Contains(ip)
				}
				assert.Truef(t, anyInRange, "the IP address returned %v is not in range of the provided CIDRs", ip)
			} else {
				assert.Error(t, err, test.errorMsg)
			}
		})
	}
}
