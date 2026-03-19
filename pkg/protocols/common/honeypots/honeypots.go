package honeypots

import (
	"strings"
)

type HoneypotSignature struct {
	Name    string
	Pattern string
	Weight  float64
}

var DefaultSignatures = []HoneypotSignature{
	{Name: "Cowrie", Pattern: "SSH-2.0-OpenSSH_7.4p1", Weight: 0.8},
	{Name: "Dionaea", Pattern: "Small HTTP server", Weight: 0.9},
	{Name: "Kippo", Pattern: "delayed_echo", Weight: 1.0},
}

func Detect(responseBody string, headers string) float64 {
	var totalWeight, matchedWeight float64
	for _, sig := range DefaultSignatures {
		totalWeight += sig.Weight
		if strings.Contains(responseBody, sig.Pattern) || strings.Contains(headers, sig.Pattern) {
			matchedWeight += sig.Weight
		}
	}
	if totalWeight == 0 { return 0 }
	return matchedWeight / totalWeight
}

