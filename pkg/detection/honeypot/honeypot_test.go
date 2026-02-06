package honeypot

import (
	"context"
	"testing"
	"time"
)

func TestNewDetector(t *testing.T) {
	opts := DefaultOptions()
	detector := NewDetector(opts)

	if detector == nil {
		t.Fatal("Expected detector to be created")
	}

	if detector.opts == nil {
		t.Fatal("Expected options to be set")
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts == nil {
		t.Fatal("Expected options to be created")
	}

	if opts.Timeout != 5*time.Second {
		t.Errorf("Expected timeout to be 5s, got %v", opts.Timeout)
	}

	if !opts.EnableSSH {
		t.Error("Expected SSH detection to be enabled")
	}

	if !opts.EnableHTTP {
		t.Error("Expected HTTP detection to be enabled")
	}

	if !opts.EnableTCP {
		t.Error("Expected TCP detection to be enabled")
	}

	if len(opts.Ports) == 0 {
		t.Error("Expected default ports to be set")
	}

	expectedPorts := []int{22, 23, 80, 443, 2222, 8080, 8443, 21, 25, 445, 3306, 5900}
	if len(opts.Ports) != len(expectedPorts) {
		t.Errorf("Expected %d ports, got %d", len(expectedPorts), len(opts.Ports))
	}

	if opts.Concurrency != 5 {
		t.Errorf("Expected concurrency to be 5, got %d", opts.Concurrency)
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		input        string
		expectedHost string
		expectedPort int
	}{
		{"example.com", "example.com", 0},
		{"example.com:22", "example.com", 22},
		{"http://example.com", "example.com", 0},
		{"https://example.com:443", "example.com", 443},
		{"ssh://example.com:2222", "example.com", 2222},
		{"192.168.1.1:80", "192.168.1.1", 80},
		{"http://example.com/path", "example.com", 0},
		{"https://example.com:8443/admin", "example.com", 8443},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			host, port := parseTarget(tt.input)
			if host != tt.expectedHost {
				t.Errorf("Expected host %s, got %s", tt.expectedHost, host)
			}
			if port != tt.expectedPort {
				t.Errorf("Expected port %d, got %d", tt.expectedPort, port)
			}
		})
	}
}

func TestSSHBannerDetection(t *testing.T) {
	detector := NewDetector(DefaultOptions())
	ctx := context.Background()

	tests := []struct {
		banner        string
		expectedType  HoneypotType
		shouldDetect  bool
		minConfidence float64
		description   string
	}{
		{
			banner:        "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
			expectedType:  HoneypotCowrie,
			shouldDetect:  true,
			minConfidence: 0.8,
			description:   "Cowrie default banner",
		},
		{
			banner:        "SSH-2.0-OpenSSH_5.1p1 Debian-5",
			expectedType:  HoneypotKippo,
			shouldDetect:  true,
			minConfidence: 0.8,
			description:   "Kippo banner",
		},
		{
			banner:        "SSH-2.0-sshesame",
			expectedType:  HoneypotSSHesame,
			shouldDetect:  true,
			minConfidence: 0.9,
			description:   "SSHesame banner",
		},
		{
			banner:        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
			expectedType:  HoneypotUnknown,
			shouldDetect:  false,
			minConfidence: 0.0,
			description:   "Legitimate modern SSH",
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			result := detector.checkSSH(ctx, "test.example.com", 22, []byte(tt.banner))

			if result == nil {
				t.Fatal("Expected result to not be nil")
			}

			if result.IsHoneypot != tt.shouldDetect {
				t.Errorf("Expected IsHoneypot=%v, got %v", tt.shouldDetect, result.IsHoneypot)
			}

			if tt.shouldDetect && result.Type != tt.expectedType {
				t.Errorf("Expected type %s, got %s", tt.expectedType, result.Type)
			}

			if tt.shouldDetect && result.Confidence < tt.minConfidence {
				t.Errorf("Expected confidence >= %f, got %f", tt.minConfidence, result.Confidence)
			}
		})
	}
}

func TestGenericBannerDetection(t *testing.T) {
	detector := NewDetector(DefaultOptions())

	tests := []struct {
		banner       string
		shouldDetect bool
		expectedType HoneypotType
		description  string
	}{
		{
			banner:       "Welcome to cowrie honeypot",
			shouldDetect: true,
			expectedType: HoneypotGenericTCP,
			description:  "Banner with 'cowrie' keyword",
		},
		{
			banner:       "This is a honeypot system",
			shouldDetect: true,
			expectedType: HoneypotGenericTCP,
			description:  "Banner with 'honeypot' keyword",
		},
		{
			banner:       "Welcome to Apache Web Server",
			shouldDetect: false,
			expectedType: HoneypotUnknown,
			description:  "Legitimate banner",
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			result := detector.analyzeGenericBanner(tt.banner, "test.example.com", 80)

			if result == nil {
				t.Fatal("Expected result to not be nil")
			}

			if result.IsHoneypot != tt.shouldDetect {
				t.Errorf("Expected IsHoneypot=%v, got %v", tt.shouldDetect, result.IsHoneypot)
			}

			if tt.shouldDetect && result.Type != tt.expectedType {
				t.Errorf("Expected type %s, got %s", tt.expectedType, result.Type)
			}
		})
	}
}

func TestDetectionResult(t *testing.T) {
	result := &DetectionResult{
		IsHoneypot: true,
		Type:       HoneypotCowrie,
		Confidence: 0.85,
		Indicators: []string{"SSH banner matches Cowrie pattern"},
		Target:     "example.com",
		Port:       22,
	}

	if !result.IsHoneypot {
		t.Error("Expected IsHoneypot to be true")
	}

	if result.Type != HoneypotCowrie {
		t.Errorf("Expected type %s, got %s", HoneypotCowrie, result.Type)
	}

	if result.Confidence != 0.85 {
		t.Errorf("Expected confidence 0.85, got %f", result.Confidence)
	}

	if len(result.Indicators) != 1 {
		t.Errorf("Expected 1 indicator, got %d", len(result.Indicators))
	}
}

func TestHoneypotTypes(t *testing.T) {
	types := []HoneypotType{
		HoneypotUnknown,
		HoneypotCowrie,
		HoneypotKippo,
		HoneypotDionaea,
		HoneypotHoneyD,
		HoneypotGlastopf,
		HoneypotConpot,
		HoneypotElasticHoney,
		HoneypotMailoney,
		HoneypotSSHesame,
		HoneypotGenericSSH,
		HoneypotGenericHTTP,
		HoneypotGenericTCP,
	}

	for _, honeypotType := range types {
		if string(honeypotType) == "" {
			t.Errorf("Expected non-empty string for honeypot type %v", honeypotType)
		}
	}
}

func TestNewTargetFilter(t *testing.T) {
	opts := DefaultOptions()
	filter := NewTargetFilter(opts, nil, nil)

	if filter == nil {
		t.Fatal("Expected filter to be created")
	}

	if filter.detector == nil {
		t.Error("Expected detector to be set")
	}

	if filter.results == nil {
		t.Error("Expected results map to be initialized")
	}
}

func TestTargetFilterGetResults(t *testing.T) {
	opts := DefaultOptions()
	filter := NewTargetFilter(opts, nil, nil)

	results := filter.GetResults()
	if results == nil {
		t.Fatal("Expected results to not be nil")
	}

	if len(results) != 0 {
		t.Errorf("Expected empty results, got %d", len(results))
	}
}

func TestTargetFilterClear(t *testing.T) {
	opts := DefaultOptions()
	filter := NewTargetFilter(opts, nil, nil)

	// Use CheckTarget to populate results instead of accessing internal field
	ctx := context.Background()
	filter.CheckTarget(ctx, "mock-detection-target")

	results := filter.GetResults()
	if len(results) < 1 {
		t.Fatal("Expected at least 1 result before clear")
	}

	filter.Clear()

	clearedResults := filter.GetResults()
	if len(clearedResults) != 0 {
		t.Errorf("Expected empty results after clear, got %d", len(clearedResults))
	}
}
