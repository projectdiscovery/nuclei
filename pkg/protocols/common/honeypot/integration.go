package honeypot

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
)

// Integration provides honeypot detection integration with nuclei engine
type Integration struct {
	detector *HoneypotDetector
	options  *protocols.ExecutorOptions
}

// NewIntegration creates a new honeypot integration
func NewIntegration(options *protocols.ExecutorOptions) *Integration {
	threshold := 10 // Default threshold
	if options.Options.HoneypotThreshold > 0 {
		threshold = options.Options.HoneypotThreshold
	}

	return &Integration{
		detector: NewHoneypotDetector(threshold),
		options:  options,
	}
}

// OnEvent handles output events and checks for honeypot indicators
func (i *Integration) OnEvent(event *output.ResultEvent) {
	if event.Host == "" {
		return
	}

	// Track vulnerability count per host
	i.detector.AddVulnerability(event.Host, event.TemplateID)

	// Check if host is likely a honeypot
	if i.detector.IsHoneypot(event.Host) {
		event.Honeypot = true
		event.HoneypotScore = i.detector.GetHoneypotScore(event.Host)
		
		// Add warning to event
		if event.Metadata == nil {
			event.Metadata = make(map[string]interface{})
		}
		event.Metadata["honeypot_detected"] = true
		event.Metadata["honeypot_score"] = event.HoneypotScore
		event.Metadata["honeypot_vuln_count"] = i.detector.GetVulnerabilityCount(event.Host)
	}
}

// IsHoneypot checks if a host is detected as honeypot
func (i *Integration) IsHoneypot(host string) bool {
	return i.detector.IsHoneypot(host)
}

// GetDetector returns the underlying detector for advanced usage
func (i *Integration) GetDetector() *HoneypotDetector {
	return i.detector
}

// Close cleans up resources
func (i *Integration) Close() {
	i.detector.ResetAll()
}
