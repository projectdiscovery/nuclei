package compiler

import (
	"fmt"
	"sync"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/console"
	"github.com/dop251/goja_nodejs/require"
	"github.com/projectdiscovery/gologger"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libbytes"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libfs"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libikev2"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libkerberos"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libldap"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libmssql"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libmysql"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libnet"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/liboracle"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libpop3"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libpostgres"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/librdp"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libredis"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/librsync"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libsmb"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libsmtp"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libssh"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libstructs"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libtelnet"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libvnc"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/global"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/libs/goconsole"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/remeh/sizedwaitgroup"
)

var (
	r                *require.Registry
	lazyRegistryInit = sync.OnceFunc(func() {
		r = new(require.Registry) // this can be shared by multiple runtimes
		// autoregister console node module with default printer it uses gologger backend
		require.RegisterNativeModule(console.ModuleName, console.RequireWithPrinter(goconsole.NewGoConsolePrinter()))
	})
	sg         sizedwaitgroup.SizedWaitGroup
	lazySgInit = sync.OnceFunc(func() {
		sg = sizedwaitgroup.New(JsVmConcurrency)
	})
)

func getRegistry() *require.Registry {
	lazyRegistryInit()
	return r
}

var gojapool = &sync.Pool{
	New: func() interface{} {
		runtime := protocolstate.NewJSRuntime()
		_ = getRegistry().Enable(runtime)
		// by default import below modules every time
		_ = runtime.Set("console", require.Require(runtime, console.ModuleName))

		// Register embedded javacript helpers
		if err := global.RegisterNativeScripts(runtime); err != nil {
			gologger.Error().Msgf("Could not register scripts: %s\n", err)
		}
		return runtime
	},
}

// executes the actual js program
func executeProgram(p *goja.Program, args *ExecuteArgs, opts *ExecuteOptions) (result goja.Value, err error) {
	// its unknown (most likely cannot be done) to limit max js runtimes at a moment without making it static
	// unlike sync.Pool which reacts to GC and its purposes is to reuse objects rather than creating new ones
	lazySgInit()
	sg.Add()
	defer sg.Done()
	runtime := gojapool.Get().(*goja.Runtime)
	defer func() {
		// reset before putting back to pool
		_ = runtime.GlobalObject().Delete("template") // template ctx
		// remove all args
		for k := range args.Args {
			_ = runtime.GlobalObject().Delete(k)
		}
		if opts != nil && opts.Cleanup != nil {
			opts.Cleanup(runtime)
		}
		gojapool.Put(runtime)
	}()
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %s", r)
		}
	}()
	// set template ctx
	_ = runtime.Set("template", args.TemplateCtx)
	// set args
	for k, v := range args.Args {
		_ = runtime.Set(k, v)
	}
	// register extra callbacks if any
	if opts != nil && opts.Callback != nil {
		if err := opts.Callback(runtime); err != nil {
			return nil, err
		}

	}
	// execute the script
	return runtime.RunProgram(p)
}

// Internal purposes i.e generating bindings
func InternalGetGeneratorRuntime() *goja.Runtime {
	runtime := gojapool.Get().(*goja.Runtime)
	return runtime
}
