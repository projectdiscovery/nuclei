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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
)

// HoneypotType represents the type of honeypot detected during analysis.
// It identifies specific honeypot systems based on fingerprinting techniques.
type HoneypotType string

const (
	// HoneypotUnknown indicates an unidentified honeypot type
	HoneypotUnknown HoneypotType = "unknown"
	// HoneypotCowrie indicates a Cowrie SSH/Telnet honeypot
	HoneypotCowrie HoneypotType = "cowrie"
	// HoneypotKippo indicates a Kippo SSH honeypot
	HoneypotKippo HoneypotType = "kippo"
	// HoneypotDionaea indicates a Dionaea malware collection honeypot
	HoneypotDionaea HoneypotType = "dionaea"
	// HoneypotHoneyD indicates a HoneyD virtual honeypot
	HoneypotHoneyD HoneypotType = "honeyd"
	// HoneypotGlastopf indicates a Glastopf web application honeypot
	HoneypotGlastopf HoneypotType = "glastopf"
	// HoneypotConpot indicates a Conpot ICS/SCADA honeypot
	HoneypotConpot HoneypotType = "conpot"
	// HoneypotElasticHoney indicates an ElasticHoney Elasticsearch honeypot
	HoneypotElasticHoney HoneypotType = "elastichoney"
	// HoneypotMailoney indicates a Mailoney SMTP honeypot
	HoneypotMailoney HoneypotType = "mailoney"
	// HoneypotSSHesame indicates an SSHesame SSH honeypot
	HoneypotSSHesame HoneypotType = "sshesame"
	// HoneypotGenericSSH indicates a generic SSH honeypot without specific identification
	HoneypotGenericSSH HoneypotType = "generic-ssh-honeypot"
	// HoneypotGenericHTTP indicates a generic HTTP honeypot without specific identification
	HoneypotGenericHTTP HoneypotType = "generic-http-honeypot"
	// HoneypotGenericTCP indicates a generic TCP honeypot without specific identification
	HoneypotGenericTCP HoneypotType = "generic-tcp-honeypot"
)

// DetectionResult holds the comprehensive result of honeypot detection for a target.
// It includes the detection status, type, confidence level, and indicators.
type DetectionResult struct {
	// IsHoneypot indicates whether the target was identified as a honeypot
	IsHoneypot bool
	// Type identifies the specific type of honeypot detected
	Type HoneypotType
	// Confidence is a score between 0.0 and 1.0 indicating detection confidence
	Confidence float64
	// Indicators contains specific evidence/signatures that led to the detection
	Indicators []string
	// Target is the hostname or IP address that was scanned
	Target string
	// Port is the network port that was checked during detection
	Port int
}

// Options contains all configuration parameters for honeypot detection.
// These options control detection behavior, protocols, ports, and concurrency.
type Options struct {
	// Timeout specifies the maximum duration for each port check attempt
	Timeout time.Duration
	// EnableSSH enables detection on SSH/Telnet ports (default: true)
	EnableSSH bool
	// EnableHTTP enables detection on HTTP/HTTPS ports (default: true)
	EnableHTTP bool
	// EnableTCP enables generic TCP banner detection (default: true)
	EnableTCP bool
	// Ports specifies the list of ports to check for honeypot indicators
	Ports []int
	// Logger is the logger instance for debug output
	Logger *gologger.Logger
	// Concurrency specifies the number of concurrent port checks per target
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

// Detector is the main honeypot detection engine responsible for analyzing targets
// and identifying honeypot indicators across multiple protocols.
type Detector struct {
	// opts contains the detection configuration and parameters
	opts *Options
	// logger is used for logging detection operations and errors
	logger *gologger.Logger
	// Precompiled regex patterns for SSH detection
	sshOldVersionRegex *regexp.Regexp
	sshLibsshRegex     *regexp.Regexp
	sshDebian7Regex    *regexp.Regexp
	sshCompatModeRegex *regexp.Regexp
	// Precompiled regex patterns for HTTP detection
	httpHoneypotRegex      *regexp.Regexp
	httpHoneytokenRegex    *regexp.Regexp
	httpServerCowrieRegex  *regexp.Regexp
	httpServerDionaeaRegex *regexp.Regexp
}

// NewDetector creates a new honeypot detector
func NewDetector(opts *Options) *Detector {
	if opts == nil {
		opts = DefaultOptions()
	}
	return &Detector{
		opts:   opts,
		logger: opts.Logger,
		// Compile SSH regex patterns once
		sshOldVersionRegex: regexp.MustCompile(`SSH-2\.0-OpenSSH_[345]\.[0-9]`),
		sshLibsshRegex:     regexp.MustCompile(`SSH-2\.0-libssh`),
		sshDebian7Regex:    regexp.MustCompile(`SSH-2\.0-OpenSSH.*Debian-4\+deb7`),
		sshCompatModeRegex: regexp.MustCompile(`SSH-1\.99-`),
		// Compile HTTP regex patterns once
		httpHoneypotRegex:      regexp.MustCompile(`(?i)honeypot`),
		httpHoneytokenRegex:    regexp.MustCompile(`(?i)honeytoken`),
		httpServerCowrieRegex:  regexp.MustCompile(`Server:\s*cowrie`),
		httpServerDionaeaRegex: regexp.MustCompile(`Server:\s*dionaea`),
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

// checkPort performs honeypot detection on a specific port.
// It returns a DetectionResult if a honeypot is detected, or nil if no detection occurs.
func (d *Detector) checkPort(ctx context.Context, host string, port int) *DetectionResult {
	// HTTP ports: skip banner read and TCP dial here; checkHTTP does its own dial
	if (port == 80 || port == 8080 || port == 443 || port == 8443) && d.opts.EnableHTTP {
		return d.checkHTTP(ctx, host, port)
	}

	// For non-HTTP ports, perform TCP dial and banner read
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
	case port == 21:
		return d.checkFTP(ctx, host, port, banner)
	case port == 25:
		return d.checkSMTP(ctx, host, port, banner)
	default:
		if len(banner) > 0 {
			return d.analyzeGenericBanner(string(banner), host, port)
		}
	}

	return result
}

// checkSSH performs SSH honeypot detection using banner analysis.
// It checks for known SSH honeypot signatures like Cowrie, Kippo, and SSHesame.
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

	// Generic SSH honeypot indicators using precompiled regex patterns
	sshHoneypotIndicators := []struct {
		regex      *regexp.Regexp
		confidence float64
		desc       string
	}{
		{d.sshOldVersionRegex, 0.5, "Very old OpenSSH version (common in honeypots)"},
		{d.sshLibsshRegex, 0.3, "libssh based server (sometimes used in honeypots)"},
		{d.sshDebian7Regex, 0.7, "Debian 7 default SSH (EOL, common honeypot)"},
		{d.sshCompatModeRegex, 0.6, "SSH-1.99 compatibility mode (unusual in modern deployments)"},
	}

	for _, indicator := range sshHoneypotIndicators {
		if indicator.regex.MatchString(bannerStr) {
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

// checkTelnet performs Telnet honeypot detection by analyzing banners.
// It identifies patterns commonly associated with Cowrie Telnet honeypots.
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

// checkHTTP performs HTTP honeypot detection by sending HTTP requests and analyzing responses.
// It detects Glastopf and other HTTP-based honeypots through pattern matching.
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

	// Generic HTTP honeypot indicators using precompiled regex patterns
	httpHoneypotIndicators := []struct {
		regex      *regexp.Regexp
		confidence float64
		desc       string
	}{
		{d.httpHoneypotRegex, 0.9, "Response contains 'honeypot' keyword"},
		{d.httpHoneytokenRegex, 0.85, "Response contains 'honeytoken' keyword"},
		{d.httpServerCowrieRegex, 0.95, "Server header identifies as Cowrie"},
		{d.httpServerDionaeaRegex, 0.95, "Server header identifies as Dionaea"},
	}

	for _, indicator := range httpHoneypotIndicators {
		if indicator.regex.MatchString(responseStr) {
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

// checkFTP performs FTP honeypot detection through banner analysis.
// It identifies FTP services that match known honeypot patterns like Dionaea.
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

// checkSMTP performs SMTP honeypot detection using banner analysis.
// It checks for SMTP banners that match Mailoney and other SMTP honeypot patterns.
func (d *Detector) checkSMTP(ctx context.Context, host string, port int, banner []byte) *DetectionResult {
	result := &DetectionResult{
		Target:     fmt.Sprintf("%s:%d", host, port),
		Port:       port,
		IsHoneypot: false,
		Type:       HoneypotUnknown,
		Indicators: make([]string, 0),
	}

	bannerStr := string(banner)
	bannerLower := strings.ToLower(bannerStr)

	// High-confidence specific honeypot banners
	if strings.Contains(bannerLower, "220 mailhoney") {
		result.IsHoneypot = true
		result.Type = HoneypotMailoney
		result.Confidence = 0.85
		result.Indicators = append(result.Indicators, "SMTP banner explicitly identifies as mailhoney")
		return result
	}

	// Generic Postfix banner - common in legitimate servers, requires secondary signals
	if strings.Contains(bannerLower, "220 localhost esmtp postfix") {
		result.Confidence += 0.35
		result.Indicators = append(result.Indicators, "Generic 'localhost ESMTP Postfix' banner (common but suspicious)")
		
		// Check for additional honeypot indicators
		if strings.Contains(bannerLower, "ubuntu") || strings.Contains(bannerLower, "debian") {
			// Real servers typically show more specific hostnames
			result.Confidence += 0.25
			result.Indicators = append(result.Indicators, "Generic OS identifier in SMTP banner")
		}
		
		if result.Confidence >= 0.6 {
			result.IsHoneypot = true
			result.Type = HoneypotMailoney
		}
	}

	return result
}

// analyzeGenericBanner analyzes a generic banner for honeypot indicators.
// It searches for common honeypot keywords in service banners.
func (d *Detector) analyzeGenericBanner(banner string, host string, port int) *DetectionResult {
	result := &DetectionResult{
		Port:       port,
		Target:     fmt.Sprintf("%s:%d", host, port),
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

// parseTarget parses a target string to extract host and port information.
// It handles various URL formats and IPv6 addresses correctly.
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
		if parsedPort, err := strconv.Atoi(p); err == nil {
			port = parsedPort
		}
	}

	return host, port
}
