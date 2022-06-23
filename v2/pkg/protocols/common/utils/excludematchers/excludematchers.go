package excludematchers

import (
	"strings"
)

// ExcludeMatchers is an instance for excluding matchers with template IDs
type ExcludeMatchers struct {
	values       map[string]struct{}
	templateIDs  map[string]struct{}
	matcherNames map[string]struct{}
}

// New returns a new exclude matchers instance
//
// Wildcard and non-wildcard values are supported.
// <template-id>:<matcher-name> is the syntax. Wildcards can be specified
// using * character for either value.
//
//  Ex- http-missing-security-headers:* skips all http-missing-security-header templates
func New(values []string) *ExcludeMatchers {
	excludeMatchers := &ExcludeMatchers{
		values:       make(map[string]struct{}),
		templateIDs:  make(map[string]struct{}),
		matcherNames: make(map[string]struct{}),
	}
	for _, value := range values {
		partValues := strings.SplitN(value, ":", 2)
		if len(partValues) < 2 {
			continue
		}

		// Handle wildcards
		if partValues[0] == "*" {
			if _, ok := excludeMatchers.matcherNames[partValues[1]]; !ok {
				excludeMatchers.matcherNames[partValues[1]] = struct{}{}
			}
		} else if partValues[1] == "*" {
			if _, ok := excludeMatchers.templateIDs[partValues[0]]; !ok {
				excludeMatchers.templateIDs[partValues[0]] = struct{}{}
			}
		} else {
			if _, ok := excludeMatchers.values[value]; !ok {
				excludeMatchers.values[value] = struct{}{}
			}
		}
	}
	return excludeMatchers
}

// Match returns true if templateID and matcherName matches the blocklist
func (e *ExcludeMatchers) Match(templateID, matcherName string) bool {
	if _, ok := e.templateIDs[templateID]; ok {
		return true
	}
	if _, ok := e.matcherNames[matcherName]; ok {
		return true
	}
	matchName := strings.Join([]string{templateID, matcherName}, ":")
	_, found := e.values[matchName]
	return found
}
