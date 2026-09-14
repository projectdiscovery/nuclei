package contextargs

import (
	"context"
	"net/http/cookiejar"
	"strings"
	"sync/atomic"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/portutil"
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
	args              *mapsutil.SyncLockMap[string, interface{}]
	templateVariables *mapsutil.SyncLockMap[string, struct{}]
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
		templateVariables: &mapsutil.SyncLockMap[string, struct{}]{
			Map:      make(map[string]struct{}),
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
	ctx.clearTemplateVariable(key)
}

func (ctx *Context) hasArgs() bool {
	return !ctx.args.IsEmpty()
}

// Merge the key-value pairs
func (ctx *Context) Merge(args map[string]interface{}) {
	_ = ctx.args.Merge(args)
	for key := range args {
		ctx.clearTemplateVariable(key)
	}
}

// MergeTemplateVariables merges values produced from template variables.
func (ctx *Context) MergeTemplateVariables(args map[string]interface{}) {
	_ = ctx.args.Merge(args)
	for key := range args {
		ctx.setTemplateVariable(key)
	}
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

// UseNetworkPort updates input with required/default network port for that template.
// The template port is used when:
//   - the input has no port at all, OR
//   - the input port is a reserved HTTP/DNS port AND the port was not explicitly
//     specified by the user (i.e. the input contains a URL scheme, meaning the
//     port was implied by the scheme, not typed by the operator).
//
// When the operator explicitly writes "target:80" (no scheme), that port is
// intentional (e.g. an SSH service running on port 80) and must not be replaced.
func (ctx *Context) UseNetworkPort(port string, excludePorts string) error {
	ignorePorts := reservedPorts
	if excludePorts != "" {
		ignorePorts = resolvePortList(strings.Split(excludePorts, ","))
		ignorePorts = sliceutil.Dedupe(ignorePorts)
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
	if inputPort == "" {
		// No port in input at all — use the template port.
		target.UpdatePort(port)
		ctx.MetaInput.Input = target.Host
		return nil
	}
	// The input has an explicit port. Only override a reserved port when the
	// input included a URL scheme (http:// / https://), which means the port was
	// implied by the scheme rather than deliberately typed by the operator.
	// A bare "host:port" form (no scheme) means the operator chose that port
	// on purpose and we must not overwrite it.
	hasScheme := strings.Contains(ctx.MetaInput.Input, "://")
	if hasScheme && stringsutil.EqualFoldAny(inputPort, ignorePorts...) {
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

// GetTemplateVariables returns values currently owned by template variable
// evaluation.
func (ctx *Context) GetTemplateVariables() map[string]interface{} {
	if ctx.templateVariables == nil || ctx.templateVariables.IsEmpty() {
		return nil
	}

	values := make(map[string]interface{})
	for key := range ctx.templateVariables.Clone().Map {
		value, ok := ctx.Get(key)
		if ok {
			values[key] = value
		}
	}

	return values
}

func (ctx *Context) setTemplateVariable(key string) {
	if ctx.templateVariables == nil {
		ctx.templateVariables = &mapsutil.SyncLockMap[string, struct{}]{
			Map:      make(map[string]struct{}),
			ReadOnly: atomic.Bool{},
		}
	}
	_ = ctx.templateVariables.Set(key, struct{}{})
}

func (ctx *Context) clearTemplateVariable(key string) {
	if ctx.templateVariables == nil {
		return
	}
	ctx.templateVariables.Delete(key)
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
		ctx:               ctx.ctx,
		MetaInput:         ctx.MetaInput.Clone(),
		args:              ctx.args.Clone(),
		templateVariables: ctx.templateVariables.Clone(),
		CookieJar:         ctx.CookieJar,
	}
	return newCtx
}

// resolvePortList converts a list of port strings (numeric or service names) to numeric port strings.
func resolvePortList(ports []string) []string {
	resolved := make([]string, 0, len(ports))
	for _, p := range ports {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if r, err := portutil.ResolvePort(p); err == nil {
			resolved = append(resolved, r)
		}
	}
	return resolved
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
