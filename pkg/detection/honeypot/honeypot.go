// Package honeypot provides honeypot detection capabilities for nuclei.
// It implements fingerprinting techniques to identify common honeypot systems
// like Cowrie (SSH), Dionaea, HoneyD, Kippo, Glastopf, and others.
package honeypot

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
)

// HoneypotType represents the type of honeypot detected
type HoneypotType string

const (
	HoneypotUnknown      HoneypotType = "unknown"
	HoneypotCowrie       HoneypotType = "cowrie"
	HoneypotKippo        HoneypotType = "kippo"
	HoneypotDionaea      HoneypotType = "dionaea"
	HoneypotHoneyD       HoneypotType = "honeyd"
	HoneypotGlastopf     HoneypotType = "glastopf"
	HoneypotConpot       HoneypotType = "conpot"
	HoneypotElasticHoney HoneypotType = "elastichoney"
	HoneypotMailoney     HoneypotType = "mailoney"
	HoneypotSSHesame     HoneypotType = "sshesame"
	HoneypotGenericSSH   HoneypotType = "generic-ssh-honeypot"
	HoneypotGenericHTTP  HoneypotType = "generic-http-honeypot"
	HoneypotGenericTCP   HoneypotType = "generic-tcp-honeypot"
)

// DetectionResult holds the result of honeypot detection
type DetectionResult struct {
	IsHoneypot bool
	Type       HoneypotType
	Confidence float64
	Indicators []string
	Target     string
	Port       int
}

// Options contains configuration for honeypot detection
type Options struct {
	Timeout     time.Duration
	EnableSSH   bool
	EnableHTTP  bool
	EnableTCP   bool
	Ports       []int
	Logger      *gologger.Logger
	Concurrency int
}

// DefaultOptions returns default detection options
func DefaultOptions() *Options {
	return &Options{
		Timeout:     5 * time.Second,
		EnableSSH:   true,
		EnableHTTP:  true,
		EnableTCP:   true,
		Ports:       []int{22, 23, 80, 443, 2222, 8080, 8443, 21, 25, 445, 3306, 5900},
		Concurrency: 5,
	}
}

// Detector is the main honeypot detection engine
type Detector struct {
	opts   *Options
	logger *gologger.Logger
}

// NewDetector creates a new honeypot detector
func NewDetector(opts *Options) *Detector {
	if opts == nil {
		opts = DefaultOptions()
	}
	return &Detector{
		opts:   opts,
		logger: opts.Logger,
	}
}

// Detect performs honeypot detection on the specified target
func (d *Detector) Detect(ctx context.Context, target string) (*DetectionResult, error) {
	result := &DetectionResult{
		Target:     target,
		IsHoneypot: false,
		Type:       HoneypotUnknown,
		Confidence: 0.0,
		Indicators: make([]string, 0),
	}

	host, port := parseTarget(target)

	var wg sync.WaitGroup
	resultChan := make(chan *DetectionResult, len(d.opts.Ports))
	semaphore := make(chan struct{}, d.opts.Concurrency)

	portsToCheck := d.opts.Ports
	if port > 0 {
		portsToCheck = []int{port}
	}

	for _, p := range portsToCheck {
		wg.Add(1)
		go func(checkPort int) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			}

			portResult := d.checkPort(ctx, host, checkPort)
			if portResult != nil && portResult.IsHoneypot {
				resultChan <- portResult
			}
		}(p)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for portResult := range resultChan {
		if portResult.Confidence > result.Confidence {
			result = portResult
		}
	}

	return result, nil
}

// checkPort performs honeypot detection on a specific port
func (d *Detector) checkPort(ctx context.Context, host string, port int) *DetectionResult {
	result := &DetectionResult{
		Target:     fmt.Sprintf("%s:%d", host, port),
		Port:       port,
		IsHoneypot: false,
		Type:       HoneypotUnknown,
		Indicators: make([]string, 0),
	}

	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, d.opts.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(d.opts.Timeout))

	banner := make([]byte, 4096)
	n, err := conn.Read(banner)
	if err != nil && err != io.EOF {
		banner = nil
	} else if n > 0 {
		banner = banner[:n]
	}

	switch {
	case port == 22 || port == 2222:
		if d.opts.EnableSSH {
			return d.checkSSH(ctx, host, port, banner)
		}
	case port == 23:
		return d.checkTelnet(ctx, host, port, banner)
	case port == 80 || port == 8080 || port == 443 || port == 8443:
		if d.opts.EnableHTTP {
			return d.checkHTTP(ctx, host, port)
		}
	case port == 21:
		return d.checkFTP(ctx, host, port, banner)
	case port == 25:
		return d.checkSMTP(ctx, host, port, banner)
	default:
		if len(banner) > 0 {
			return d.analyzeGenericBanner(string(banner), port)
		}
	}

	return result
}

// checkSSH performs SSH honeypot detection
func (d *Detector) checkSSH(ctx context.Context, host string, port int, banner []byte) *DetectionResult {
	result := &DetectionResult{
		Target:     fmt.Sprintf("%s:%d", host, port),
		Port:       port,
		IsHoneypot: false,
		Type:       HoneypotUnknown,
		Indicators: make([]string, 0),
	}

	bannerStr := string(banner)

	// Cowrie detection patterns
	cowriePatterns := []string{
		"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
		"SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.4",
		"SSH-2.0-OpenSSH_6.0p1",
	}

	for _, pattern := range cowriePatterns {
		if strings.Contains(bannerStr, pattern) {
			result.IsHoneypot = true
			result.Type = HoneypotCowrie
			result.Confidence = 0.85
			result.Indicators = append(result.Indicators, fmt.Sprintf("SSH banner matches Cowrie pattern: %s", pattern))
			return result
		}
	}

	// Kippo detection patterns
	kippoPatterns := []string{
		"SSH-2.0-OpenSSH_5.1p1 Debian-5",
		"SSH-1.99-OpenSSH_4.7p1",
	}

	for _, pattern := range kippoPatterns {
		if strings.Contains(bannerStr, pattern) {
			result.IsHoneypot = true
			result.Type = HoneypotKippo
			result.Confidence = 0.80
			result.Indicators = append(result.Indicators, fmt.Sprintf("SSH banner matches Kippo pattern: %s", pattern))
			return result
		}
	}

	// SSHesame detection
	if strings.Contains(bannerStr, "SSH-2.0-sshesame") {
		result.IsHoneypot = true
		result.Type = HoneypotSSHesame
		result.Confidence = 0.95
		result.Indicators = append(result.Indicators, "SSH banner explicitly identifies as sshesame")
		return result
	}

	// Generic SSH honeypot indicators
	sshHoneypotIndicators := []struct {
		pattern    string
		confidence float64
		desc       string
	}{
		{`SSH-2\.0-OpenSSH_[345]\.[0-9]`, 0.5, "Very old OpenSSH version (common in honeypots)"},
		{`SSH-2\.0-libssh`, 0.3, "libssh based server (sometimes used in honeypots)"},
		{`SSH-2\.0-OpenSSH.*Debian-4\+deb7`, 0.7, "Debian 7 default SSH (EOL, common honeypot)"},
		{`SSH-1\.99-`, 0.6, "SSH-1.99 compatibility mode (unusual in modern deployments)"},
	}

	for _, indicator := range sshHoneypotIndicators {
		re := regexp.MustCompile(indicator.pattern)
		if re.MatchString(bannerStr) {
			result.Confidence += indicator.confidence * 0.5
			result.Indicators = append(result.Indicators, indicator.desc)
		}
	}

	if result.Confidence >= 0.6 {
		result.IsHoneypot = true
		result.Type = HoneypotGenericSSH
	}

	return result
}

// checkTelnet performs Telnet honeypot detection
func (d *Detector) checkTelnet(ctx context.Context, host string, port int, banner []byte) *DetectionResult {
	result := &DetectionResult{
		Target:     fmt.Sprintf("%s:%d", host, port),
		Port:       port,
		IsHoneypot: false,
		Type:       HoneypotUnknown,
		Indicators: make([]string, 0),
	}

	bannerStr := string(banner)

	cowrieTelnetPatterns := []string{
		"BusyBox v1.19.4",
		"BusyBox v1.20.2",
		"BusyBox built-in shell",
		"DD-WRT v24-sp2",
	}

	for _, pattern := range cowrieTelnetPatterns {
		if strings.Contains(bannerStr, pattern) {
			result.IsHoneypot = true
			result.Type = HoneypotCowrie
			result.Confidence = 0.75
			result.Indicators = append(result.Indicators, fmt.Sprintf("Telnet banner matches Cowrie pattern: %s", pattern))
			return result
		}
	}

	return result
}

// checkHTTP performs HTTP honeypot detection
func (d *Detector) checkHTTP(ctx context.Context, host string, port int) *DetectionResult {
	result := &DetectionResult{
		Target:     fmt.Sprintf("%s:%d", host, port),
		Port:       port,
		IsHoneypot: false,
		Type:       HoneypotUnknown,
		Indicators: make([]string, 0),
	}

	isHTTPS := port == 443 || port == 8443

	var conn net.Conn
	var err error
	address := fmt.Sprintf("%s:%d", host, port)

	if isHTTPS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: d.opts.Timeout}, "tcp", address, tlsConfig)
	} else {
		conn, err = net.DialTimeout("tcp", address, d.opts.Timeout)
	}

	if err != nil {
		return nil
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(d.opts.Timeout))

	httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", host)
	_, err = conn.Write([]byte(httpReq))
	if err != nil {
		return nil
	}

	response := make([]byte, 8192)
	n, _ := conn.Read(response)
	if n == 0 {
		return nil
	}

	responseStr := string(response[:n])

	// Glastopf detection
	glastopfPatterns := []string{
		"glastopf",
		"Blog Comments",
	}
	for _, pattern := range glastopfPatterns {
		if strings.Contains(strings.ToLower(responseStr), pattern) {
			result.IsHoneypot = true
			result.Type = HoneypotGlastopf
			result.Confidence = 0.85
			result.Indicators = append(result.Indicators, fmt.Sprintf("HTTP response matches Glastopf pattern: %s", pattern))
			return result
		}
	}

	// Generic HTTP honeypot indicators
	httpHoneypotIndicators := []struct {
		pattern    string
		confidence float64
		desc       string
	}{
		{`(?i)honeypot`, 0.9, "Response contains 'honeypot' keyword"},
		{`(?i)honeytoken`, 0.85, "Response contains 'honeytoken' keyword"},
		{`Server:\s*cowrie`, 0.95, "Server header identifies as Cowrie"},
		{`Server:\s*dionaea`, 0.95, "Server header identifies as Dionaea"},
	}

	for _, indicator := range httpHoneypotIndicators {
		re := regexp.MustCompile(indicator.pattern)
		if re.MatchString(responseStr) {
			result.Confidence += indicator.confidence * 0.5
			result.Indicators = append(result.Indicators, indicator.desc)
		}
	}

	if result.Confidence >= 0.6 {
		result.IsHoneypot = true
		if result.Type == HoneypotUnknown {
			result.Type = HoneypotGenericHTTP
		}
	}

	return result
}

// checkFTP performs FTP honeypot detection
func (d *Detector) checkFTP(ctx context.Context, host string, port int, banner []byte) *DetectionResult {
	result := &DetectionResult{
		Target:     fmt.Sprintf("%s:%d", host, port),
		Port:       port,
		IsHoneypot: false,
		Type:       HoneypotUnknown,
		Indicators: make([]string, 0),
	}

	bannerStr := string(banner)

	dionaeaFTPPatterns := []string{
		"220 DiskStation FTP server ready",
		"220 FTP server ready",
	}

	for _, pattern := range dionaeaFTPPatterns {
		if strings.Contains(bannerStr, pattern) {
			result.Indicators = append(result.Indicators, fmt.Sprintf("FTP banner matches potential honeypot: %s", pattern))
			result.Confidence += 0.4
		}
	}

	if result.Confidence >= 0.6 {
		result.IsHoneypot = true
		result.Type = HoneypotDionaea
	}

	return result
}

// checkSMTP performs SMTP honeypot detection
func (d *Detector) checkSMTP(ctx context.Context, host string, port int, banner []byte) *DetectionResult {
	result := &DetectionResult{
		Target:     fmt.Sprintf("%s:%d", host, port),
		Port:       port,
		IsHoneypot: false,
		Type:       HoneypotUnknown,
		Indicators: make([]string, 0),
	}

	bannerStr := string(banner)

	mailoneyPatterns := []string{
		"220 localhost ESMTP Postfix",
		"220 mailhoney",
	}

	for _, pattern := range mailoneyPatterns {
		if strings.Contains(strings.ToLower(bannerStr), strings.ToLower(pattern)) {
			result.IsHoneypot = true
			result.Type = HoneypotMailoney
			result.Confidence = 0.70
			result.Indicators = append(result.Indicators, fmt.Sprintf("SMTP banner matches honeypot pattern: %s", pattern))
			return result
		}
	}

	return result
}

// analyzeGenericBanner analyzes a generic banner for honeypot indicators
func (d *Detector) analyzeGenericBanner(banner string, port int) *DetectionResult {
	result := &DetectionResult{
		Port:       port,
		Target:     "",
		IsHoneypot: false,
		Type:       HoneypotUnknown,
		Indicators: make([]string, 0),
	}

	honeypotKeywords := []string{
		"honeypot",
		"honeyd",
		"cowrie",
		"kippo",
		"dionaea",
		"glastopf",
		"conpot",
		"honeytrap",
	}

	bannerLower := strings.ToLower(banner)
	for _, keyword := range honeypotKeywords {
		if strings.Contains(bannerLower, keyword) {
			result.IsHoneypot = true
			result.Type = HoneypotGenericTCP
			result.Confidence = 0.85
			result.Indicators = append(result.Indicators, fmt.Sprintf("Banner contains honeypot keyword: %s", keyword))
			return result
		}
	}

	return result
}

// parseTarget parses a target string to extract host and port
func parseTarget(target string) (string, int) {
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "ssh://")

	if idx := strings.Index(target, "/"); idx != -1 {
		target = target[:idx]
	}

	host := target
	port := 0

	// Use net.SplitHostPort for proper IPv6 support
	h, p, err := net.SplitHostPort(target)
	if err == nil {
		host = h
		fmt.Sscanf(p, "%d", &port)
	}

	return host, port
}
