package compiler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
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
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/libs/goconsole"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	stringsutil "github.com/projectdiscovery/utils/strings"
	syncutil "github.com/projectdiscovery/utils/sync"
)

const (
	exportToken   = "Export"
	exportAsToken = "ExportAs"
)

var (
	r                *require.Registry
	lazyRegistryInit = sync.OnceFunc(func() {
		r = new(require.Registry) // this can be shared by multiple runtimes
		// autoregister console node module with default printer it uses gologger backend
		require.RegisterNativeModule(console.ModuleName, console.RequireWithPrinter(goconsole.NewGoConsolePrinter()))
	})
	pooljsc    *syncutil.AdaptiveWaitGroup
	lazySgInit = sync.OnceFunc(func() {
		pooljsc, _ = syncutil.New(syncutil.WithSize(PoolingJsVmConcurrency))
	})
	sgResizeCheck = func(ctx context.Context) {
		// resize check point
		if pooljsc.Size != PoolingJsVmConcurrency {
			if err := pooljsc.Resize(ctx, PoolingJsVmConcurrency); err != nil {
				gologger.Warning().Msgf("Could not resize workpool: %s\n", err)
			}
		}
	}
)

var gojapool = &sync.Pool{
	New: func() interface{} {
		return createNewRuntime()
	},
}

func executeWithRuntime(runtime *goja.Runtime, p *goja.Program, args *ExecuteArgs, opts *ExecuteOptions) (result goja.Value, err error) {
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

// ExecuteProgram executes a compiled program with the default options.
// it deligates if a particular program should run in a pooled or non-pooled runtime
func ExecuteProgram(p *goja.Program, args *ExecuteArgs, opts *ExecuteOptions) (result goja.Value, err error) {
	if opts.Source == nil {
		// not-recommended anymore
		return executeWithoutPooling(p, args, opts)
	}
	if !stringsutil.ContainsAny(*opts.Source, exportAsToken, exportToken) {
		// not-recommended anymore
		return executeWithoutPooling(p, args, opts)
	}
	return executeWithPoolingProgram(p, args, opts)
}

// executes the actual js program
func executeWithPoolingProgram(p *goja.Program, args *ExecuteArgs, opts *ExecuteOptions) (result goja.Value, err error) {
    // Initialize pool if not already done
    lazySgInit()
    sgResizeCheck(opts.Context)

    // Acquire a slot in the work group and ensure it's released
    pooljsc.Add()
    defer pooljsc.Done()

    // Get a runtime from the pool and ensure it's put back
    runtime := gojapool.Get().(*goja.Runtime)
    defer gojapool.Put(runtime)

    // Prepare for cleanup
    defer func() {
        _ = runtime.GlobalObject().Delete("template") // template ctx
        for k := range args.Args {
            _ = runtime.GlobalObject().Delete(k)
        }
        if opts != nil && opts.Cleanup != nil {
            opts.Cleanup(runtime)
        }
    }()
    defer func() {
        if r := recover(); r != nil {
            err = fmt.Errorf("panic: %s", r)
        }
    }()

    // Set template context and arguments
    _ = runtime.Set("template", args.TemplateCtx)
    for k, v := range args.Args {
        _ = runtime.Set(k, v)
    }

    // Register extra callbacks if any
    if opts != nil && opts.Callback != nil {
        if err := opts.Callback(runtime); err != nil {
            return nil, err
        }
    }

    // Prepare for exports
    var buff bytes.Buffer
    opts.exports = make(map[string]interface{})
    defer func() {
        _ = runtime.GlobalObject().Delete(exportAsToken)
        _ = runtime.GlobalObject().Delete(exportToken)
    }()

    // Register export functions
    _ = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
        Name:        "Export",
        Signatures:  []string{"Export(value any)"},
        Description: "Converts a given value to a string and is appended to output of script",
        FuncDecl: func(call goja.FunctionCall, runtime *goja.Runtime) goja.Value {
            if len(call.Arguments) == 0 {
                return goja.Null()
            }
            for _, arg := range call.Arguments {
                if out := stringify(arg, runtime); out != "" {
                    buff.WriteString(out)
                }
            }
            return goja.Null()
        },
    })
    _ = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
        Name:        "ExportAs",
        Signatures:  []string{"ExportAs(key string, value any)"},
        Description: "Exports given value with specified key and makes it available in DSL and response",
        FuncDecl: func(call goja.FunctionCall, runtime *goja.Runtime) goja.Value {
            if len(call.Arguments) != 2 {
                panic(runtime.ToValue("ExportAs expects 2 arguments"))
            }
            key := call.Argument(0).String()
            value := call.Argument(1)
            opts.exports[key] = stringify(value, runtime)
            return goja.Null()
        },
    })

    val, err := executeWithRuntime(runtime, p, args, opts)
    if err != nil {
        return nil, err
    }
    if val.Export() != nil {
        buff.WriteString(stringify(val, runtime))
    }
    return runtime.ToValue(buff.String()), nil
}
