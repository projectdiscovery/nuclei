package contextargs

import (
	"net/http/cookiejar"
	"sync"
)

type Context struct {
	Input     string
	CookieJar *cookiejar.Jar

	// Access to Args must use lock strategies to prevent data races
	*sync.RWMutex
	Args map[string]interface{}
}

func New() Context {
	return Context{Args: make(map[string]interface{}), RWMutex: &sync.RWMutex{}}
}
