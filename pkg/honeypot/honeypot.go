package honeypot

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

var globalDet *Detector

// Init initializes global detector from options
func Init(options *types.Options) {
	if options.HoneypotDetectionEnabled {
		globalDet = New(options)
	}
}

// Record records a match and returns whether host is a honeypot
func Record(host, templateID string, options *types.Options) bool {
	if globalDet == nil && options.HoneypotDetectionEnabled {
		Init(options)
	}
	if globalDet != nil {
		return globalDet.RecordMatch(host, templateID)
	}
	return false
}

// IsHoneypot reports if host is considered a honeypot
func IsHoneypot(host string) bool {
	if globalDet == nil {
		return false
	}
	return globalDet.IsHoneypot(host)
}

// Count returns current match count
func Count(host string) int {
	if globalDet == nil {
		return 0
	}
	return globalDet.GetMatchCount(host)
}
