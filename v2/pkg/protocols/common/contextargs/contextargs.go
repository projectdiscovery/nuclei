package contextargs

import (
	"net/http/cookiejar"

	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	mapsutil "github.com/projectdiscovery/utils/maps"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
)

var (
	// reservedPorts contains list of reserved ports for non-network requests in nuclei
	reservedPorts           = []string{"80", "443", "8080", "8443", "8081", "53"}
	reservedNetworkPortName = "networkPort"
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
	return &Context{MetaInput: &MetaInput{}}
}

// Create a new contextargs instance with input string
func NewWithInput(input string) *Context {
	return &Context{MetaInput: &MetaInput{Input: input}}
}

func (ctx *Context) initialize() {
	ctx.args = &mapsutil.SyncLockMap[string, interface{}]{Map: mapsutil.Map[string, interface{}]{}}
}

// Set the specific key-value pair
func (ctx *Context) Set(key string, value interface{}) {
	if !ctx.isInitialized() {
		ctx.initialize()
	}

	_ = ctx.args.Set(key, value)
}

func (ctx *Context) isInitialized() bool {
	return ctx.args != nil
}

func (ctx *Context) hasArgs() bool {
	return ctx.isInitialized() && !ctx.args.IsEmpty()
}

// UpdatePortFromConstants gets networkPort from constants and updates input port when necessary
func (ctx *Context) UpdatePortFromConstants(constants map[string]interface{}) error {
	var port string
	if val, ok := constants[reservedNetworkPortName]; ok {
		port = types.ToString(val)
		if port == "" {
			return nil
		}
	}

	target, err := urlutil.Parse(ctx.MetaInput.Input)
	if err != nil {
		return err
	}
	inputPort := target.Port()
	if inputPort == "" || stringsutil.EqualFoldAny(inputPort, reservedPorts...) {
		// replace port with networkPort
		target.UpdatePort(port)
		ctx.MetaInput.Input = target.Host
	}
	return nil
}

// Get the value with specific key if exists
func (ctx *Context) Get(key string) (interface{}, bool) {
	if !ctx.hasArgs() {
		return nil, false
	}

	return ctx.args.Get(key)
}

func (ctx *Context) GetAll() *mapsutil.SyncLockMap[string, interface{}] {
	if !ctx.hasArgs() {
		return nil
	}

	return ctx.args.Clone()
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
	return ctx.hasArgs()
}

func (ctx *Context) Clone() *Context {
	newCtx := &Context{
		MetaInput: ctx.MetaInput.Clone(),
		args:      ctx.args,
		CookieJar: ctx.CookieJar,
	}
	return newCtx
}
