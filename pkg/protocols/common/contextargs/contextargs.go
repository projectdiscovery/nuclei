package contextargs

import (
	"context"
	"net/http/cookiejar"
	"strings"
	"sync/atomic"

	"github.com/projectdiscovery/gologger"
	mapsutil "github.com/projectdiscovery/utils/maps"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
)

var (
	// reservedPorts contains list of reserved ports for non-network requests in nuclei
	reservedPorts = []string{"80", "443", "8080", "8443", "8081", "53"}
)

// Context implements a shared context struct to share information across multiple templates within a workflow
type Context struct {
	ctx context.Context

	// Meta is the target for the executor
	MetaInput *MetaInput

	// CookieJar shared within workflow's http templates
	CookieJar *cookiejar.Jar

	// Args is a workflow shared key-value store
	args *mapsutil.SyncLockMap[string, interface{}]
}

// Create a new contextargs instance
func New(ctx context.Context) *Context {
	return NewWithInput(ctx, "")
}

// NewWithMetaInput creates a new contextargs instance with meta input
func NewWithMetaInput(ctx context.Context, input *MetaInput) *Context {
	n := New(ctx)
	n.MetaInput = input
	return n
}

// Create a new contextargs instance with input string
func NewWithInput(ctx context.Context, input string) *Context {
	jar, err := cookiejar.New(nil)
	if err != nil {
		gologger.Error().Msgf("contextargs: could not create cookie jar: %s\n", err)
	}
	metaInput := NewMetaInput()
	metaInput.Input = input
	return &Context{
		ctx:       ctx,
		MetaInput: metaInput,
		CookieJar: jar,
		args: &mapsutil.SyncLockMap[string, interface{}]{
			Map:      make(map[string]interface{}),
			ReadOnly: atomic.Bool{},
		},
	}
}

// Context returns the context of the current contextargs
func (ctx *Context) Context() context.Context {
	return ctx.ctx
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

// UseNetworkPort updates input with required/default network port for that template
// but is ignored if input/target contains non-http ports like 80,8080,8081 etc
func (ctx *Context) UseNetworkPort(port string, excludePorts string) error {
	ignorePorts := reservedPorts
	if excludePorts != "" {
		// TODO: add support for service names like http,https,ssh etc once https://github.com/projectdiscovery/netdb is ready
		ignorePorts = sliceutil.Dedupe(strings.Split(excludePorts, ","))
	}
	if port == "" {
		// if template does not contain port, do nothing
		return nil
	}
	target, err := urlutil.Parse(ctx.MetaInput.Input)
	if err != nil {
		return err
	}
	inputPort := target.Port()
	if inputPort == "" || stringsutil.EqualFoldAny(inputPort, ignorePorts...) {
		// replace port with networkPort
		target.UpdatePort(port)
		ctx.MetaInput.Input = target.Host
	}
	return nil
}

// Port returns the port of the target
func (ctx *Context) Port() string {
	target, err := urlutil.Parse(ctx.MetaInput.Input)
	if err != nil {
		return ""
	}
	return target.Port()
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
		ctx:       ctx.ctx,
		MetaInput: ctx.MetaInput.Clone(),
		args:      ctx.args.Clone(),
		CookieJar: ctx.CookieJar,
	}
	return newCtx
}

// GetCopyIfHostOutdated returns a new contextargs if the host is outdated
func GetCopyIfHostOutdated(ctx *Context, url string) *Context {
	if ctx.MetaInput.Input == "" {
		newctx := ctx.Clone()
		newctx.MetaInput.Input = url
		return newctx
	}
	orig, _ := urlutil.Parse(ctx.MetaInput.Input)
	newURL, _ := urlutil.Parse(url)
	if orig != nil && newURL != nil && orig.Host != newURL.Host {
		newCtx := ctx.Clone()
		newCtx.MetaInput.Input = newURL.Host
		return newCtx
	}
	return ctx
}
