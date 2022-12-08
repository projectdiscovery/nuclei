package hybrid

import (
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
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
		input.hostMap.Scan(func(k, _ []byte) error {
			var metainput contextargs.MetaInput
			if err := metainput.Unmarshal(string(k)); err != nil {
				return err
			}
			got = append(got, metainput.Input)
			return nil
		})
		require.ElementsMatch(t, tt.expected, got, "could not get correct cidrs")
		input.Close()
	}
}

type mockDnsHandler struct{}

func (this *mockDnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)
	switch r.Question[0].Qtype {
	case dns.TypeA:
		msg.Authoritative = true
		domain := msg.Question[0].Name
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("128.199.158.128"),
		})
	case dns.TypeAAAA:
		msg.Authoritative = true
		domain := msg.Question[0].Name
		msg.Answer = append(msg.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			AAAA: net.ParseIP("2400:6180:0:d0::91:1001"),
		})
	}
	_ = w.WriteMsg(&msg)
}

func Test_scanallips_normalizeStoreInputValue(t *testing.T) {
	srv := &dns.Server{Addr: ":" + strconv.Itoa(61234), Net: "udp"}
	srv.Handler = &mockDnsHandler{}

	go func() {
		err := srv.ListenAndServe()
		require.Nil(t, err)
	}()

	defaultOpts := types.DefaultOptions()
	defaultOpts.InternalResolversList = []string{"127.0.0.1:61234"}
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
			expected: []string{"128.199.158.128", "2400:6180:0:d0::91:1001"},
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

		input.Set(tt.hostname)
		// scan
		got := []string{}
		input.hostMap.Scan(func(k, v []byte) error {
			var metainput contextargs.MetaInput
			if err := metainput.Unmarshal(string(k)); err != nil {
				return err
			}
			got = append(got, metainput.CustomIP)
			return nil
		})
		require.ElementsMatch(t, tt.expected, got, "could not get correct ips")
		input.Close()
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
			var metainput contextargs.MetaInput
			if err := metainput.Unmarshal(string(k)); err != nil {
				return err
			}
			got = append(got, metainput.Input)
			return nil
		})
		// read the expected IPs from the file
		fileContent, err := os.ReadFile(tt.expectedOutputFile)
		require.Nil(t, err, "could not read the expectedOutputFile file")

		items := strings.Split(strings.ReplaceAll(string(fileContent), "\r\n", "\n"), "\n")

		require.ElementsMatch(t, items, got, "could not get correct ips")
	}
}
