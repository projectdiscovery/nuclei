package contextargs

import (
	"net/http/cookiejar"
	"sync"

	"github.com/projectdiscovery/gologger"
	maputils "github.com/projectdiscovery/utils/maps"
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
	args maputils.Map[string, interface{}]
}

// Create a new contextargs instance
func New() *Context {
	return NewWithInput("")
}

// Create a new contextargs instance with input string
func NewWithInput(input string) *Context {
	jar, err := cookiejar.New(nil)
	if err != nil {
		gologger.Error().Msgf("Could not create cookie jar: %s\n", err)
	}
	return &Context{MetaInput: &MetaInput{Input: input}, CookieJar: jar, RWMutex: &sync.RWMutex{}, args: make(maputils.Map[string, interface{}])}
}

func (ctx *Context) set(key string, value interface{}) {
	ctx.Lock()
	defer ctx.Unlock()

	ctx.args.Set(key, value)
}

// Set the specific key-value pair
func (ctx *Context) Set(key string, value interface{}) {
	ctx.set(key, value)
}

// isEmpty check if the args is empty
func (ctx *Context) isEmpty() bool {
	ctx.Lock()
	defer ctx.Unlock()
	return !ctx.args.IsEmpty()
}

func (ctx *Context) hasArgs() bool {
	return ctx.isEmpty()
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

func (ctx *Context) getAll() maputils.Map[string, interface{}] {
	ctx.RLock()
	defer ctx.RUnlock()

	return ctx.args.Clone()
}

func (ctx *Context) GetAll() maputils.Map[string, interface{}] {
	if !ctx.hasArgs() {
		return nil
	}

	return ctx.getAll()
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

func (ctx *Context) Clone() *Context {
	newCtx := &Context{
		MetaInput: ctx.MetaInput.Clone(),
		RWMutex:   ctx.RWMutex,
		args:      ctx.args.Clone(),
		CookieJar: ctx.CookieJar,
	}
	return newCtx
}
