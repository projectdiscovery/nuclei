// From Katana
package scope

import (
	"fmt"
	"net/url"
	"regexp"
)

// Manager manages scope for crawling process
type Manager struct {
	inScope    []*regexp.Regexp
	outOfScope []*regexp.Regexp
	noScope    bool
}

// NewManager returns a new scope manager for crawling
func NewManager(inScope, outOfScope []string) (*Manager, error) {
	manager := &Manager{}

	for _, regex := range inScope {
		if compiled, err := regexp.Compile(regex); err != nil {
			return nil, fmt.Errorf("could not compile regex %s: %s", regex, err)
		} else {
			manager.inScope = append(manager.inScope, compiled)
		}
	}
	for _, regex := range outOfScope {
		if compiled, err := regexp.Compile(regex); err != nil {
			return nil, fmt.Errorf("could not compile regex %s: %s", regex, err)
		} else {
			manager.outOfScope = append(manager.outOfScope, compiled)
		}
	}
	if len(manager.inScope) == 0 && len(manager.outOfScope) == 0 {
		manager.noScope = true
	}
	return manager, nil
}

// Validate returns true if the URL matches scope rules
func (m *Manager) Validate(URL *url.URL) (bool, error) {
	if m.noScope {
		return true, nil
	}

	urlStr := URL.String()

	urlValidated, err := m.validateURL(urlStr)
	if err != nil {
		return false, err
	}
	if urlValidated {
		return true, nil
	}
	return false, nil
}

func (m *Manager) validateURL(URL string) (bool, error) {
	for _, item := range m.outOfScope {
		if item.MatchString(URL) {
			return false, nil
		}
	}
	if len(m.inScope) == 0 {
		return true, nil
	}

	var inScopeMatched bool
	for _, item := range m.inScope {
		if item.MatchString(URL) {
			inScopeMatched = true
			break
		}
	}
	return inScopeMatched, nil
}
