package contextargs

import (
	"net/http/cookiejar"

	"github.com/projectdiscovery/gologger"
	maputils "github.com/projectdiscovery/utils/maps"
)

// Context implements a shared context struct to share information across multiple templates within a workflow
type Context struct {
	// Meta is the target for the executor
	MetaInput *MetaInput

	// CookieJar shared within workflow's http templates
	CookieJar *cookiejar.Jar
	// Args is a workflow shared key-value store
	args maputils.SyncLockMap[string, interface{}]
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
	syncMap := maputils.SyncLockMap[string, interface{}]{
		Map: make(map[string]interface{}),
	}
	return &Context{MetaInput: &MetaInput{Input: input}, CookieJar: jar, args: syncMap}
}

// Set the specific key-value pair
func (ctx *Context) Set(key string, value interface{}) {
	if err := ctx.args.Set(key, value); err != nil {
		gologger.Error().Msgf("contextargs: could not set key: %s\n", err)
	}
}

// Get the value with specific key if exists
func (ctx *Context) Get(key string) (interface{}, bool) {
	return ctx.args.Get(key)
}

func (ctx *Context) GetAll() maputils.Map[string, interface{}] {
	return ctx.args.GetAll()
}

func (ctx *Context) ForEach(f func(string, interface{}) error) {
	if err := ctx.args.Iterate(f); err != nil {
		gologger.Error().Msgf("contextargs: could not iterate: %s\n", err)
	}
}

// Has check if the key exists
func (ctx *Context) Has(key string) bool {
	return ctx.args.Has(key)
}

func (ctx *Context) HasArgs() bool {
	return !ctx.args.IsEmpty()
}

func (ctx *Context) Clone() *Context {
	newCtx := &Context{
		MetaInput: ctx.MetaInput.Clone(),
		args:      *ctx.args.Clone(),
		CookieJar: ctx.CookieJar,
	}
	return newCtx
}
