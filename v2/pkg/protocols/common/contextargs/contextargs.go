package contextargs

import (
	"net/http/cookiejar"
	"sync/atomic"

	"github.com/projectdiscovery/gologger"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// Context implements a shared context struct to share information across multiple templates within a workflow
type Context struct {
	// Meta is the target for the executor
	MetaInput *MetaInput

	// CookieJar shared within workflow's http templates
	CookieJar *cookiejar.Jar

	// Args is a workflow shared key-value store
	args *mapsutil.SyncLockMap[string, interface{}]
}

// Create a new contextargs instance
func New() *Context {
	return NewWithInput("")
}

// Create a new contextargs instance with input string
func NewWithInput(input string) *Context {
	jar, err := cookiejar.New(nil)
	if err != nil {
		gologger.Error().Msgf("contextargs: could not create cookie jar: %s\n", err)
	}
	return &Context{
		MetaInput: &MetaInput{Input: input},
		CookieJar: jar,
		args: &mapsutil.SyncLockMap[string, interface{}]{
			Map:      make(map[string]interface{}),
			ReadOnly: atomic.Bool{},
		},
	}
}

// Set the specific key-value pair
func (ctx *Context) Set(key string, value interface{}) {
	_ = ctx.args.Set(key, value)
}

func (ctx *Context) hasArgs() bool {
	return !ctx.args.IsEmpty()
}

// Merge the key-value pairs
func (ctx *Context) Merge(args map[string]interface{}) {
	_ = ctx.args.Merge(args)
}

// Add the specific key-value pair
func (ctx *Context) Add(key string, v interface{}) {
	values, ok := ctx.args.Get(key)
	if !ok {
		ctx.Set(key, v)
	}

	// If the key exists, append the value to the existing value
	switch v := v.(type) {
	case []string:
		if values, ok := values.([]string); ok {
			values = append(values, v...)
			ctx.Set(key, values)
		}
	case string:
		if values, ok := values.(string); ok {
			tmp := []string{values, v}
			ctx.Set(key, tmp)
		}
	default:
		values, _ := ctx.Get(key)
		ctx.Set(key, []interface{}{values, v})
	}
}

// Get the value with specific key if exists
func (ctx *Context) Get(key string) (interface{}, bool) {
	if !ctx.hasArgs() {
		return nil, false
	}

	return ctx.args.Get(key)
}

func (ctx *Context) GetAll() map[string]interface{} {
	if !ctx.hasArgs() {
		return nil
	}

	return ctx.args.Clone().Map
}

func (ctx *Context) ForEach(f func(string, interface{})) {
	_ = ctx.args.Iterate(func(k string, v interface{}) error {
		f(k, v)
		return nil
	})
}

// Has check if the key exists
func (ctx *Context) Has(key string) bool {
	return ctx.hasArgs() && ctx.args.Has(key)
}

func (ctx *Context) HasArgs() bool {
	return !ctx.args.IsEmpty()
}

func (ctx *Context) Clone() *Context {
	newCtx := &Context{
		MetaInput: ctx.MetaInput.Clone(),
		args:      ctx.args,
		CookieJar: ctx.CookieJar,
	}
	return newCtx
}
