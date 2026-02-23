package xss

import (
	"regexp"
	"strings"
)

// Analyzer implements the XSS context detection logic for Nuclei
type Analyzer struct{}

func (a *Analyzer) Name() string {
	return "xss-context-analyzer"
}

var (
	// Optimized regex patterns to prevent ReDoS (as requested by Neo/CodeRabbit)
	attrRegex    = regexp.MustCompile(`(?i)=\s*(?:["\'][^"\'>]*|[^"\'\s>]+)$`)
	scriptRegex  = regexp.MustCompile(`(?i)<script\b[^>]*>(?:(?!</script>)[\s\S])*$`)
	commentRegex = regexp.MustCompile(`(?i)<!--(?:(?!-->)[\s\S])*$`)
	tagBodyRegex = regexp.MustCompile(`(?i)>[^<]*$`)
)

func (a *Analyzer) Analyze(input string) string {
	if len(input) == 0 {
		return "raw_html"
	}

	// Limit input size to prevent resource exhaustion (CWE-400)
	if len(input) > 4096 {
		input = input[len(input)-4096:]
	}

	if scriptRegex.MatchString(input) {
		return "script"
	}
	if commentRegex.MatchString(input) {
		return "comment"
	}
	if attrRegex.MatchString(input) {
		return "attribute"
	}
	if tagBodyRegex.MatchString(input) {
		return "tag_body"
	}

	return "raw_html"
}
