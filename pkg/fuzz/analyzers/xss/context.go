package xss

import (
	"regexp"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
)

// Context represents the XSS context type
type Context int

const (
	ContextUnknown Context = iota
	ContextScript          // JavaScript execution context
	ContextAttribute       // HTML attribute context
	ContextHTML            // HTML injection context
	ContextURL             // URL context
	ContextCSS             // CSS context
)

// String returns the string representation of the context
func (c Context) String() string {
	switch c {
	case ContextScript:
		return "ContextScript"
	case ContextAttribute:
		return "ContextAttribute"
	case ContextHTML:
		return "ContextHTML"
	case ContextURL:
		return "ContextURL"
	case ContextCSS:
		return "ContextCSS"
	default:
		return "ContextUnknown"
	}
}

// ContextAnalyzer analyzes the XSS context in HTTP responses
type ContextAnalyzer struct {
	// Regex patterns for context detection
	javascriptURIPattern    *regexp.Regexp
	scriptBlockPattern      *regexp.Regexp
	srcdocPattern           *regexp.Regexp
	htmlTagPattern          *regexp.Regexp
	attributePattern        *regexp.Regexp
	caseInsensitivePatterns []*regexp.Regexp
}

// NewContextAnalyzer creates a new context analyzer
func NewContextAnalyzer() *ContextAnalyzer {
	return &ContextAnalyzer{
		// Pattern for javascript: URIs (case-insensitive)
		javascriptURIPattern: regexp.MustCompile(`(?i)javascript\s*:`),
		
		// Pattern for script blocks
		scriptBlockPattern: regexp.MustCompile(`(?i)<\s*script[^>]*>`),
		
		// Pattern for srcdoc attributes (HTML injection context)
		srcdocPattern: regexp.MustCompile(`(?i)\bsrcdoc\s*=\s*["']`),
		
		// Pattern for HTML tags
		htmlTagPattern: regexp.MustCompile(`<[^>]+>`),
		
		// Pattern for HTML attributes
		attributePattern: regexp.MustCompile(`\w+\s*=\s*["'][^"']*["']`),
		
		// Case-insensitive patterns for reflection detection
		caseInsensitivePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)<\s*img[^>]+src\s*=`),
			regexp.MustCompile(`(?i)<\s*a[^>]+href\s*=`),
			regexp.MustCompile(`(?i)<\s*iframe[^>]+src\s*=`),
			regexp.MustCompile(`(?i)<\s*embed[^>]+src\s*=`),
			regexp.MustCompile(`(?i)<\s*object[^>]+data\s*=`),
		},
	}
}

// AnalyzeContext analyzes the context of a reflection in an HTTP response
// and returns the appropriate context type
func (a *ContextAnalyzer) AnalyzeContext(response string, reflection string) Context {
	// Check for javascript: URIs - these should be treated as executable script context
	if a.javascriptURIPattern.MatchString(response) {
		// Verify the reflection is actually in a javascript: URI context
		lowerResponse := strings.ToLower(response)
		lowerReflection := strings.ToLower(reflection)
		
		// Find javascript: URI and check if reflection is within it
		jsURIIndex := strings.Index(lowerResponse, "javascript:")
		if jsURIIndex != -1 {
			// Find the closing quote or space
			endIndex := strings.IndexAny(lowerResponse[jsURIIndex:], `"'\s>`)
			if endIndex != -1 {
				uriContent := lowerResponse[jsURIIndex : jsURIIndex+endIndex]
				if strings.Contains(uriContent, lowerReflection) {
					return ContextScript
				}
			}
		}
	}
	
	// Check for srcdoc attributes - these allow full HTML injection
	if a.srcdocPattern.MatchString(response) {
		return ContextHTML
	}
	
	// Check for script blocks - but DON'T treat them as executable context
	// if the reflection is inside a <script> tag that's not actually executable
	// (e.g., in a JSON block or template)
	if a.scriptBlockPattern.MatchString(response) {
		// Check if we're in a JSON script block (not executable)
		if strings.Contains(strings.ToLower(response), `<script type="application/json">`) ||
			strings.Contains(strings.ToLower(response), `<script type='application/json'>`) {
			return ContextUnknown // Not executable
		}
		
		// Check if reflection is actually inside the script tag
		scriptMatches := a.scriptBlockPattern.FindAllStringIndex(response, -1)
		for _, match := range scriptMatches {
			if len(match) == 2 {
				// Find closing script tag
				closeTag := regexp.MustCompile(`(?i)</\s*script\s*>`)
				closeMatches := closeTag.FindAllStringIndex(response[match[1]:], -1)
				if len(closeMatches) > 0 {
					scriptContent := response[match[1] : match[1]+closeMatches[0][0]]
					if strings.Contains(scriptContent, reflection) {
						return ContextScript
					}
				}
			}
		}
	}
	
	// Case-insensitive reflection detection
	// This fixes the issue where reflection detection was case-sensitive
	lowerResponse := strings.ToLower(response)
	lowerReflection := strings.ToLower(reflection)
	
	if strings.Contains(lowerResponse, lowerReflection) {
		// Check for HTML tag context
		if a.htmlTagPattern.MatchString(response) {
			// Check if it's in an attribute
			if a.attributePattern.MatchString(response) {
				return ContextAttribute
			}
			return ContextHTML
		}
	}
	
	// Check for URL context
	if strings.Contains(response, "http://") || strings.Contains(response, "https://") {
		if strings.Contains(response, reflection) {
			return ContextURL
		}
	}
	
	// Check for CSS context
	if strings.Contains(response, "style=") || strings.Contains(response, "<style>") {
		if strings.Contains(response, reflection) {
			return ContextCSS
		}
	}
	
	return ContextUnknown
}

// IsCaseInsensitiveMatch checks if reflection exists in response (case-insensitive)
func (a *ContextAnalyzer) IsCaseInsensitiveMatch(response, reflection string) bool {
	lowerResponse := strings.ToLower(response)
	lowerReflection := strings.ToLower(reflection)
	return strings.Contains(lowerResponse, lowerReflection)
}

// GetExecutableContexts returns a list of contexts that allow code execution
func GetExecutableContexts() []Context {
	return []Context{
		ContextScript,
		ContextHTML, // HTML injection can lead to XSS
		ContextURL,  // URL can contain javascript:
	}
}

// IsExecutableContext checks if a context allows code execution
func IsExecutableContext(ctx Context) bool {
	executableContexts := GetExecutableContexts()
	for _, execCtx := range executableContexts {
		if ctx == execCtx {
			return true
		}
	}
	return false
}
