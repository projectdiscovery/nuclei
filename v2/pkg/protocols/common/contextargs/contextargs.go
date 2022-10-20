package contextargs

import (
	"net/http/cookiejar"
	"sync"

	"golang.org/x/exp/maps"
)

// Context implements a shared context struct to share information across multiple templates within a workflow
type Context struct {
	// Meta is the target for the executor
	MetaInput *MetaInput

	// CookieJar shared within workflow's http templates
	CookieJar *cookiejar.Jar

	// Access to Args must use lock strategies to prevent data races
	*sync.RWMutex
	// Args is a workflow shared key-value store
	args Args
}

// Create a new contextargs instance
func New() *Context {
	return &Context{MetaInput: &MetaInput{}}
}

// Create a new contextargs instance with input string
func NewWithInput(input string) *Context {
	return &Context{MetaInput: &MetaInput{Input: input}}
}

func (ctx *Context) initialize() {
	ctx.args = newArgs()
	ctx.RWMutex = &sync.RWMutex{}
}

func (ctx *Context) set(key string, value interface{}) {
	ctx.Lock()
	defer ctx.Unlock()

	ctx.args.Set(key, value)
}

// Set the specific key-value pair
func (ctx *Context) Set(key string, value interface{}) {
	if !ctx.isInitialized() {
		ctx.initialize()
	}

	ctx.set(key, value)
}

func (ctx *Context) isInitialized() bool {
	return ctx.args != nil
}

func (ctx *Context) hasArgs() bool {
	return ctx.isInitialized() && !ctx.args.IsEmpty()
}

func (ctx *Context) get(key string) (interface{}, bool) {
	ctx.RLock()
	defer ctx.RUnlock()

	return ctx.args.Get(key)
}

// Get the value with specific key if exists
func (ctx *Context) Get(key string) (interface{}, bool) {
	if !ctx.hasArgs() {
		return nil, false
	}

	return ctx.get(key)
}

func (ctx *Context) GetAll() Args {
	if !ctx.hasArgs() {
		return nil
	}

	return maps.Clone(ctx.args)
}

func (ctx *Context) ForEach(f func(string, interface{})) {
	ctx.RLock()
	defer ctx.RUnlock()

	for k, v := range ctx.args {
		f(k, v)
	}
}

func (ctx *Context) has(key string) bool {
	ctx.RLock()
	defer ctx.RUnlock()

	return ctx.args.Has(key)
}

// Has check if the key exists
func (ctx *Context) Has(key string) bool {
	return ctx.hasArgs() && ctx.has(key)
}

func (ctx *Context) HasArgs() bool {
	return ctx.hasArgs()
}
