package contextargs

import (
	"net/http/cookiejar"
	"sync"
)

// Context implements a shared context struct to share information across multiple templates within a workflow
type Context struct {
	// Input target for the executor
	Input string
	// CookieJar shared within workflow's http templates
	CookieJar *cookiejar.Jar

	// Access to Args must use lock strategies to prevent data races
	*sync.RWMutex
	// Args is a workflow shared key-value store
	Args map[string]interface{}
}

// Create a new contextargs instance
func New() Context {
	return Context{Args: make(map[string]interface{}), RWMutex: &sync.RWMutex{}}
}
