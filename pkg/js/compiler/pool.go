package compiler

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"sync"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/console"
	"github.com/dop251/goja_nodejs/require"
	"github.com/kitabisa/go-ci"
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
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
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

	// TODO(dwisiswant0): remove this once we get the RCA.
	defer func() {
		if ci.IsCI() {
			return
		}

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
	// its unknown (most likely cannot be done) to limit max js runtimes at a moment without making it static
	// unlike sync.Pool which reacts to GC and its purposes is to reuse objects rather than creating new ones
	lazySgInit()
	sgResizeCheck(opts.Context)

	pooljsc.Add()
	defer pooljsc.Done()
	runtime := gojapool.Get().(*goja.Runtime)
	defer gojapool.Put(runtime)
	var buff bytes.Buffer
	opts.exports = make(map[string]interface{})

	defer func() {
		// remove below functions from runtime
		_ = runtime.GlobalObject().Delete(exportAsToken)
		_ = runtime.GlobalObject().Delete(exportToken)
	}()
	// register export functions
	_ = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name:        "Export", // we use string instead of const for documentation generation
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
	// register exportAs function
	_ = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name:        "ExportAs", // Export
		Signatures:  []string{"ExportAs(key string,value any)"},
		Description: "Exports given value with specified key and makes it available in DSL and response",
		FuncDecl: func(call goja.FunctionCall, runtime *goja.Runtime) goja.Value {
			if len(call.Arguments) != 2 {
				// this is how goja expects errors to be returned
				// and internally it is done same way for all errors
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
		// append last value to output
		buff.WriteString(stringify(val, runtime))
	}
	// and return it as result
	return runtime.ToValue(buff.String()), nil
}

// Internal purposes i.e generating bindings
func InternalGetGeneratorRuntime() *goja.Runtime {
	runtime := gojapool.Get().(*goja.Runtime)
	return runtime
}

func getRegistry() *require.Registry {
	lazyRegistryInit()
	return r
}

func createNewRuntime() *goja.Runtime {
	runtime := protocolstate.NewJSRuntime()
	_ = getRegistry().Enable(runtime)
	// by default import below modules every time
	_ = runtime.Set("console", require.Require(runtime, console.ModuleName))

	// Register embedded javacript helpers
	if err := global.RegisterNativeScripts(runtime); err != nil {
		gologger.Error().Msgf("Could not register scripts: %s\n", err)
	}
	return runtime
}

// stringify converts a given value to string
// if its a struct it will be marshalled to json
func stringify(gojaValue goja.Value, runtime *goja.Runtime) string {
	value := gojaValue.Export()
	if value == nil {
		return ""
	}
	kind := reflect.TypeOf(value).Kind()
	if kind == reflect.Struct || kind == reflect.Ptr && reflect.ValueOf(value).Elem().Kind() == reflect.Struct {
		// in this case we must use JSON.stringify to convert to string
		// because json.Marshal() utilizes json tags when marshalling
		// but goja has custom implementation of json.Marshal() which does not
		// since we have been using `to_json` in all our examples we must stick to it
		// marshal structs or struct pointers to json automatically
		jsonStringify, ok := goja.AssertFunction(runtime.Get("to_json"))
		if ok {
			result, err := jsonStringify(goja.Undefined(), gojaValue)
			if err == nil {
				return result.String()
			}
		}
		// unlikely but if to_json throwed some error use native json.Marshal
		val := value
		if kind == reflect.Ptr {
			val = reflect.ValueOf(value).Elem().Interface()
		}
		bin, err := json.Marshal(val)
		if err == nil {
			return string(bin)
		}
	}
	// for everything else stringify
	return fmt.Sprintf("%+v", value)
}
