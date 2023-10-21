package normalizer

import (
	"fmt"
	"regexp"
)

// DefaultTextPatterns is a list of regex patterns for the text normalizer
var DefaultTextPatterns = []string{
	// emailAddress
	`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}`,
	// ipAddress
	`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`,
	// uuid
	`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
	// relativeDates
	`(?:[0-9]{1,2}\s(?:days?|weeks?|months?|years?)\s(?:ago|from\snow))`,
	// priceAmounts
	`[\$€£¥]\s*\d+(?:\.\d{1,2})?`,
	// phoneNumbers
	`(?:\+?1[0-9]{3}|0[0-9]{2})[ -]?\d{3}[ -]?\d{4}`,
	// ssnNumbers
	`[\$€£¥]\s*\d+(?:\.\d{1,2})?`,
	// timestampRegex
	`(?:(?:[0-9]{4}-[0-9]{2}-[0-9]{2})|(?:(?:[0-9]{2}\/){2}[0-9]{4}))\s(?:[0-9]{2}:[0-9]{2}:[0-9]{2})`,
}

// TextNormalizer is a normalizer for text
type TextNormalizer struct {
	// patterns is a list of regex patterns for the text normalizer
	patterns []*regexp.Regexp
}

// NewTextNormalizer returns a new TextNormalizer
//
// patterns is a list of regex patterns for the text normalizer
// DefaultTextPatterns is used if patterns is nil. See DefaultTextPatterns for more info.
func NewTextNormalizer(patterns []string) (*TextNormalizer, error) {
	var compiledPatterns []*regexp.Regexp
	for _, pattern := range DefaultTextPatterns {
		pattern := pattern
		compiled, err := regexp.Compile(fmt.Sprintf("\\b%s\\b", pattern))
		if err != nil {
			return nil, fmt.Errorf("error compiling default pattern %s: %v", pattern, err)
		}
		compiledPatterns = append(compiledPatterns, compiled)
	}
	for _, pattern := range patterns {
		pattern := pattern
		compiledPattern, err := regexp.Compile(fmt.Sprintf("\\b%s\\b", pattern))
		if err != nil {
			return nil, fmt.Errorf("error compiling pattern %s: %v", pattern, err)
		}
		compiledPatterns = append(compiledPatterns, compiledPattern)
	}
	return &TextNormalizer{patterns: compiledPatterns}, nil
}

// Apply applies the patterns to the text and returns the normalized text
func (n *TextNormalizer) Apply(text string) string {
	for _, pattern := range n.patterns {
		pattern := pattern
		text = pattern.ReplaceAllString(text, "")
	}
	return text
}
