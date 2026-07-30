package runner

import (
	"net"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/network"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	httpproto "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	jsproto "github.com/projectdiscovery/nuclei/v3/pkg/protocols/javascript"
)

func TestHostAndExplicitPort(t *testing.T) {
	cases := []struct{ in, host, port string }{
		{"127.0.0.1", "127.0.0.1", ""},
		{"127.0.0.1:6379", "127.0.0.1", "6379"},
		{"http://example.com:8080", "example.com", "8080"},
		{"https://example.com", "example.com", ""},
	}
	for _, c := range cases {
		h, p := hostAndExplicitPort(c.in)
		if h != c.host || p != c.port {
			t.Errorf("hostAndExplicitPort(%q) = (%q,%q), want (%q,%q)", c.in, h, p, c.host, c.port)
		}
	}
}

func TestIsNumericPort(t *testing.T) {
	for _, p := range []string{"80", "6379", "65535", "1"} {
		if !isNumericPort(p) {
			t.Errorf("isNumericPort(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"ftp", "{{Port}}", "0", "70000", "", "80a"} {
		if isNumericPort(p) {
			t.Errorf("isNumericPort(%q) = true, want false", p)
		}
	}
}

// TestTCPNetworkOnlyPorts locks in the losslessness guards: only single-protocol
// network templates with concrete numeric TCP ports are eligible for pruning.
func TestTCPNetworkOnlyPorts(t *testing.T) {
	netTmpl := func(addr []string, port string) *templates.Template {
		return &templates.Template{RequestsNetwork: []*network.Request{{Address: addr, Port: port}}}
	}

	t.Run("concrete tcp port eligible", func(t *testing.T) {
		ports, ok := tcpNetworkOnlyPorts(netTmpl([]string{"{{Hostname}}"}, "6379,6380"))
		if !ok || len(ports) != 2 {
			t.Fatalf("want ok with 2 ports, got ok=%v ports=%v", ok, ports)
		}
	})
	t.Run("tls address still tcp", func(t *testing.T) {
		if _, ok := tcpNetworkOnlyPorts(netTmpl([]string{"tls://{{Hostname}}"}, "6379")); !ok {
			t.Fatal("tls:// should remain eligible (still TCP)")
		}
	})
	t.Run("udp address rejected", func(t *testing.T) {
		if _, ok := tcpNetworkOnlyPorts(netTmpl([]string{"udp://{{Hostname}}"}, "161")); ok {
			t.Fatal("udp:// must be ineligible — a TCP probe cannot prove UDP unreachability")
		}
	})
	t.Run("service-name port rejected", func(t *testing.T) {
		if _, ok := tcpNetworkOnlyPorts(netTmpl([]string{"{{Hostname}}"}, "ftp")); ok {
			t.Fatal("service-name port must be ineligible")
		}
	})
	t.Run("dynamic port rejected", func(t *testing.T) {
		if _, ok := tcpNetworkOnlyPorts(netTmpl([]string{"{{Hostname}}"}, "{{Port}}")); ok {
			t.Fatal("template-var port must be ineligible")
		}
	})
	t.Run("empty port rejected", func(t *testing.T) {
		if _, ok := tcpNetworkOnlyPorts(netTmpl([]string{"{{Hostname}}"}, "")); ok {
			t.Fatal("empty port (uses input port) must be ineligible")
		}
	})
	t.Run("mixed protocol rejected", func(t *testing.T) {
		mixed := netTmpl([]string{"{{Hostname}}"}, "6379")
		mixed.RequestsHTTP = []*httpproto.Request{{}}
		if _, ok := tcpNetworkOnlyPorts(mixed); ok {
			t.Fatal("template with an HTTP request must be ineligible")
		}
	})
	t.Run("javascript protocol rejected", func(t *testing.T) {
		js := &templates.Template{RequestsJavascript: []*jsproto.Request{{}}}
		if _, ok := tcpNetworkOnlyPorts(js); ok {
			t.Fatal("javascript template must be ineligible (opaque dial protocol)")
		}
	})
}

func TestClassifyDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen:", err)
	}
	defer ln.Close()
	d := &net.Dialer{}
	if got := classifyDial(d.DialContext, ln.Addr().String(), reachabilityProbeTimeout); got != portOpen {
		t.Errorf("classifyDial(open) = %v, want portOpen", got)
	}
	// an unused low port on loopback should refuse quickly
	if got := classifyDial(d.DialContext, "127.0.0.1:1", reachabilityProbeTimeout); got != portClosed {
		t.Errorf("classifyDial(closed) = %v, want portClosed", got)
	}
}
