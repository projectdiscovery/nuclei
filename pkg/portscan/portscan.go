// Package portscan implements a fast TCP connect port scanner used by the
// -ps flag to expand bare hosts into host:port targets before templates run.
package portscan

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultPorts is the default port set scanned by -ps, covering the common
// web, database and infrastructure services of a typical server.
var DefaultPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
	1433, 1521, 2049, 2375, 3000, 3306, 3389, 5432, 5900, 6379, 7001, 8000,
	8080, 8081, 8443, 8888, 9000, 9090, 9200, 11211, 27017,
}

// tlsPorts get the https scheme when open; httpPorts get http; everything
// else is emitted as a bare host:port for network templates.
var (
	tlsPorts  = map[int]bool{443: true, 465: true, 587: true, 636: true, 8443: true, 8883: true, 9443: true}
	httpPorts = map[int]bool{80: true, 8000: true, 8008: true, 8080: true, 8081: true, 8888: true, 8880: true, 3000: true, 5000: true, 9000: true, 9090: true}
)

// maxPortRangeSize bounds a single range spec so typos such as "1-999999"
// cannot allocate unreasonable port lists.
const maxPortRangeSize = 65535

// ParsePorts expands user supplied port specs ("8080", "8000-8090") into a
// deduplicated ascending port list, as accepted by -ps-ports.
func ParsePorts(specs []string) ([]int, error) {
	seen := make(map[int]bool)
	var out []int
	add := func(port int) error {
		if port < 1 || port > 65535 || seen[port] {
			if port < 1 || port > 65535 {
				return fmt.Errorf("port %d out of range 1-65535", port)
			}
			return nil
		}
		seen[port] = true
		out = append(out, port)
		return nil
	}
	for _, raw := range specs {
		spec := strings.TrimSpace(raw)
		if spec == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(spec, "-")
		if !isRange {
			n, err := strconv.Atoi(spec)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", spec)
			}
			if err := add(n); err != nil {
				return nil, err
			}
			continue
		}
		start, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return nil, fmt.Errorf("invalid port range %q", spec)
		}
		end, err := strconv.Atoi(strings.TrimSpace(hi))
		if err != nil {
			return nil, fmt.Errorf("invalid port range %q", spec)
		}
		if start > end {
			start, end = end, start
		}
		if end-start >= maxPortRangeSize {
			return nil, fmt.Errorf("port range %q too large", spec)
		}
		for p := start; p <= end; p++ {
			if err := add(p); err != nil {
				return nil, err
			}
		}
	}
	sort.Ints(out)
	return out, nil
}

// Scanner performs concurrent TCP connect scans.
type Scanner struct {
	Ports       []int
	Concurrency int
	Timeout     time.Duration
	// TLSScan probes open TLS ports for a certificate subject, enriching
	// the report; it can be disabled in tests.
	TLSScan bool
}

// New returns a scanner for the given ports (DefaultPorts when empty).
func New(ports []int) *Scanner {
	if len(ports) == 0 {
		ports = DefaultPorts
	}
	return &Scanner{Ports: ports, Concurrency: 1000, Timeout: 2 * time.Second, TLSScan: true}
}

// OpenPorts scans one host and returns its open ports in ascending order.
func (s *Scanner) OpenPorts(host string) []int {
	var (
		mu   sync.Mutex
		open []int
		wg   sync.WaitGroup
		gate = make(chan struct{}, s.Concurrency)
	)
	for _, port := range s.Ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			gate <- struct{}{}
			defer func() { <-gate }()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), s.Timeout)
			if err != nil {
				return
			}
			_ = conn.Close()
			mu.Lock()
			open = append(open, port)
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	sort.Ints(open)
	return open
}

// Target is one discovered service endpoint.
type Target struct {
	Host string
	Port int
	URL  string // scheme-qualified when the port is known to speak (h)ttp
	TLS  string // certificate subject when TLS probing found one
}

// Expand turns each input into per-open-port targets. Inputs that already
// carry an explicit port are kept untouched; inputs without one are scanned
// and expanded, preserving the original path.
func (s *Scanner) Expand(inputs []string) []Target {
	var out []Target
	for _, input := range inputs {
		u, err := url.Parse(input)
		if err != nil || u.Host == "" {
			// bare host or host:port without scheme
			host, port := splitHostPort(input)
			if port != "" {
				out = append(out, Target{Host: host, Port: mustAtoi(port), URL: input})
				continue
			}
			out = append(out, s.expandHost(input, "")...)
			continue
		}
		if u.Port() != "" {
			out = append(out, Target{Host: u.Hostname(), Port: mustAtoi(u.Port()), URL: input})
			continue
		}
		out = append(out, s.expandHost(u.Hostname(), u.Path)...)
	}
	return out
}

// expandHost scans host and builds targets, appending path when non-empty.
func (s *Scanner) expandHost(host, path string) []Target {
	var out []Target
	for _, port := range s.OpenPorts(host) {
		t := Target{Host: host, Port: port}
		switch {
		case tlsPorts[port]:
			t.URL = fmt.Sprintf("https://%s:%d%s", host, port, cleanPath(path))
			if s.TLSScan {
				t.TLS = s.certSubject(host, port)
			}
		case httpPorts[port]:
			t.URL = fmt.Sprintf("http://%s:%d%s", host, port, cleanPath(path))
		default:
			t.URL = fmt.Sprintf("%s:%d", host, port)
		}
		out = append(out, t)
	}
	return out
}

// certSubject returns the leaf certificate subject of a TLS port, best effort.
func (s *Scanner) certSubject(host string, port int) string {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: s.Timeout}, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return ""
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return ""
	}
	subject := certs[0].Subject.CommonName
	if subject == "" {
		subject = strings.Join(certs[0].DNSNames, ",")
	}
	return subject
}

// splitHostPort splits "host:port" without requiring a scheme.
func splitHostPort(input string) (string, string) {
	if host, port, err := net.SplitHostPort(input); err == nil {
		return host, port
	}
	return input, ""
}

func mustAtoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func cleanPath(path string) string {
	if path == "/" {
		return ""
	}
	return path
}
