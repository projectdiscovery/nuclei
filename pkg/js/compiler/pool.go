package compiler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/goja_nodejs/console"
	"github.com/projectdiscovery/goja_nodejs/require"
	"github.com/projectdiscovery/gologger"
	stringsutil "github.com/projectdiscovery/utils/strings"
	syncutil "github.com/projectdiscovery/utils/sync"

	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libbytes"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libdcerpc"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libdcom"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libfs"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libgrpc"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libikev2"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libkerberos"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libkrbforge"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libkrbroast"
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
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libscmr"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libsecretsdump"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libsmb"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libsmtp"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libssh"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libstructs"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libtelnet"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libtsch"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libvnc"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libwmi"
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

// errRuntimeTerminationTimeout is returned by session when the
// goroutine running goja.Runtime.RunProgram fails to terminate within the
// grace period after an interrupt was raised. When this error is returned
// the runtime MUST NOT be touched (no cleanup, no reuse, no Put back to
// the pool) because the orphaned goroutine is still operating on it; any
// concurrent access would race with goja's per-runtime state and can
// trigger a fatal "concurrent map read and map write" runtime panic.
//
// See https://github.com/projectdiscovery/nuclei/issues/7376.
var errRuntimeTerminationTimeout = errors.New("nuclei js runtime: program failed to terminate after interrupt")

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

// ExecuteProgram executes a compiled program with the default options.
// it deligates if a particular program should run in a pooled or non-pooled runtime
func ExecuteProgram(ctx context.Context, p *goja.Program, args *ExecuteArgs, opts *ExecuteOptions) (goja.Value, error) {
	if opts == nil {
		opts = &ExecuteOptions{}
	}
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
	if opts == nil {
		opts = &ExecuteOptions{}
	}
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

	var buff bytes.Buffer
	opts.exports = make(map[string]interface{})

	session := newSession(sessionConfig{
		ctx:     ctx,
		runtime: runtime,
		program: p,
		args:    args,
		opts:    opts,
		prepareRuntime: func(runtime *goja.Runtime) error {
			registerExportHelpers(runtime, opts, &buff)
			return nil
		},
		cleanupRuntime: func(runtime *goja.Runtime) {
			_ = runtime.GlobalObject().Delete(exportAsToken)
			_ = runtime.GlobalObject().Delete(exportToken)
		},
		finalizeResult: func(runtime *goja.Runtime, val goja.Value) (goja.Value, error) {
			if val.Export() != nil {
				// append last value to output
				buff.WriteString(stringify(val, runtime))
			}
			// and return it as result
			return runtime.ToValue(buff.String()), nil
		},
		returnRuntime: func(runtime *goja.Runtime) {
			gojapool.Put(runtime)
		},
		releaseSlot:          pooljsc.Done,
		releaseAbandonedSlot: pooljsc.Done,
		onAbandon: func(err error) {
			gologger.Warning().Msgf("js runtime did not terminate after interrupt; abandoning it to avoid concurrent use: %s", err)
		},
	})
	return session.run()
}

func registerExportHelpers(runtime *goja.Runtime, opts *ExecuteOptions, buff *bytes.Buffer) {
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
	if kind == reflect.Struct || kind == reflect.Pointer && reflect.ValueOf(value).Elem().Kind() == reflect.Struct {
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
		if kind == reflect.Pointer {
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
