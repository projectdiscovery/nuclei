package honeypot

import "strings"

var signatures = []string{
	"cowrie",
	"dionaea",
	"kippo",
	"elasticpot",
	"glastopf",
	"honeypot",
}

// Detect returns true if response appears to be from a honeypot
func Detect(serverHeader string, body string) bool {
	s := strings.ToLower(serverHeader + " " + body)

	for _, sig := range signatures {
		if strings.Contains(s, sig) {
			return true
		}
	}
	return false
}

