package compiler

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/Mzack9999/goja"
	"github.com/Mzack9999/goja_nodejs/console"
	"github.com/Mzack9999/goja_nodejs/require"
	"github.com/projectdiscovery/gologger"
	stringsutil "github.com/projectdiscovery/utils/strings"
	syncutil "github.com/projectdiscovery/utils/sync"

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
)

const (
	exportToken   = "Export"
	exportAsToken = "ExportAs"
)

type gojaRunResult struct {
	result goja.Value
	err    error
}

var (
	lazyRegistryInit = sync.OnceFunc(func() {
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

func executeWithRuntime(ctx context.Context, runtime *goja.Runtime, p *goja.Program, args *ExecuteArgs, opts *ExecuteOptions) (goja.Value, error) {
	runtime.ClearInterrupt()

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
		runtime.RemoveContextValue("executionId")
		runtime.RemoveContextValue("ctx")
	}()

	// set template ctx
	_ = runtime.Set("template", args.TemplateCtx)
	// set args
	for k, v := range args.Args {
		_ = runtime.Set(k, v)
	}

	runtime.SetContextValue("executionId", opts.ExecutionId)
	runtime.SetContextValue("ctx", ctx)
	enableRequire(runtime)

	// register extra callbacks if any
	if opts != nil && opts.Callback != nil {
		if err := opts.Callback(runtime); err != nil {
			return nil, err
		}
	}

	resultChan := make(chan gojaRunResult, 2)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				resultChan <- gojaRunResult{err: fmt.Errorf("panic: %s", r)}
			}
		}()

		result, err := runtime.RunProgram(p)
		resultChan <- gojaRunResult{result, err}
	}()

	select {
	case <-ctx.Done():
		runtime.Interrupt(ctx.Err())
		select {
		case r := <-resultChan:
			return r.result, r.err
		case <-time.After(time.Second):
			return nil, fmt.Errorf("timeout waiting for js runtime to terminate: %w", ctx.Err())
		}
	case r := <-resultChan:
		return r.result, r.err
	}
}

// ExecuteProgram executes a compiled program with the default options.
// it deligates if a particular program should run in a pooled or non-pooled runtime
func ExecuteProgram(ctx context.Context, p *goja.Program, args *ExecuteArgs, opts *ExecuteOptions) (goja.Value, error) {
	if opts.Source == nil {
		// not-recommended anymore
		return executeWithoutPooling(ctx, p, args, opts)
	}
	if !stringsutil.ContainsAny(*opts.Source, exportAsToken, exportToken) {
		// not-recommended anymore
		return executeWithoutPooling(ctx, p, args, opts)
	}
	return executeWithPoolingProgram(ctx, p, args, opts)
}

// executes the actual js program
func executeWithPoolingProgram(ctx context.Context, p *goja.Program, args *ExecuteArgs, opts *ExecuteOptions) (goja.Value, error) {
	// its unknown (most likely cannot be done) to limit max js runtimes at a moment without making it static
	// unlike sync.Pool which reacts to GC and its purposes is to reuse objects rather than creating new ones
	lazySgInit()
	sgResizeCheck(ctx)

	// Acquire a pool slot, respecting the execution deadline. Returns
	// immediately if the context has already expired.
	if err := pooljsc.AddWithContext(ctx); err != nil {
		return nil, err
	}

	runtime := gojapool.Get().(*goja.Runtime)
	defer func() {
		gojapool.Put(runtime)
		pooljsc.Done()
	}()

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

	val, err := executeWithRuntime(ctx, runtime, p, args, opts)
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

func enableRequire(runtime *goja.Runtime) {
	lazyRegistryInit()
	_ = require.NewRegistry(require.WithLoader(newSourceLoader(runtime))).Enable(runtime)
}

func newSourceLoader(runtime *goja.Runtime) require.SourceLoader {
	return func(path string) ([]byte, error) {
		executionID := ""
		if value, ok := runtime.GetContextValue("executionId"); ok {
			if id, ok := value.(string); ok {
				executionID = id
			}
		}

		normalizedPath, err := protocolstate.NormalizePathWithExecutionId(executionID, path)
		if err != nil {
			return nil, err
		}

		return require.DefaultSourceLoader(normalizedPath)
	}
}

func createNewRuntime() *goja.Runtime {
	runtime := protocolstate.NewJSRuntime()
	enableRequire(runtime)
	// by default import below modules every time
	_ = runtime.Set("console", require.Require(runtime, console.ModuleName))

	// Register embedded javascript helpers
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
		// unlikely but if to_json threw some error use native json.Marshal
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
