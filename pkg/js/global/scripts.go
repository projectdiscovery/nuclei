package global

import (
	"bytes"
	"context"
	"embed"
	"math/rand"
	"net"
	"reflect"
	"time"

	"github.com/dop251/goja"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/vardump"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/utils/errkit"
	errorutil "github.com/projectdiscovery/utils/errors"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var (
	//go:embed js
	embedFS embed.FS

	//go:embed exports.js
	exports string
	// knownPorts is a list of known ports for protocols implemented in nuclei
	knowPorts = []string{"80", "443", "8080", "8081", "8443", "53"}
)

// default imported modules
// there might be other methods to achieve this
// but this is most straightforward
var (
	defaultImports = `
	  var structs = require("nuclei/structs");
	  var bytes = require("nuclei/bytes");
	`
)

// initBuiltInFunc initializes runtime with builtin functions
func initBuiltInFunc(runtime *goja.Runtime) {

	_ = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name:        "Rand",
		Signatures:  []string{"Rand(n int) []byte"},
		Description: "Rand returns a random byte slice of length n",
		FuncDecl: func(n int) []byte {
			b := make([]byte, n)
			for i := range b {
				b[i] = byte(rand.Intn(255))
			}
			return b
		},
	})

	_ = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name:        "RandInt",
		Signatures:  []string{"RandInt() int"},
		Description: "RandInt returns a random int",
		FuncDecl: func() int64 {
			return rand.Int63()
		},
	})

	_ = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "log",
		Signatures: []string{
			"log(msg string)",
			"log(msg map[string]interface{})",
		},
		Description: "log prints given input to stdout with [JS] prefix for debugging purposes ",
		FuncDecl: func(call goja.FunctionCall) goja.Value {
			arg := call.Argument(0).Export()
			switch value := arg.(type) {
			case string:
				gologger.DefaultLogger.Print().Msgf("[%v] %v", aurora.BrightCyan("JS"), value)
			case map[string]interface{}:
				gologger.DefaultLogger.Print().Msgf("[%v] %v", aurora.BrightCyan("JS"), vardump.DumpVariables(value))
			default:
				gologger.DefaultLogger.Print().Msgf("[%v] %v", aurora.BrightCyan("JS"), value)
			}
			return call.Argument(0)
		},
	})

	_ = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "getNetworkPort",
		Signatures: []string{
			"getNetworkPort(port string, defaultPort string) string",
		},
		Description: "getNetworkPort registers defaultPort and returns defaultPort if it is a colliding port with other protocols",
		FuncDecl: func(call goja.FunctionCall) goja.Value {
			inputPort := call.Argument(0).String()
			if inputPort == "" || stringsutil.EqualFoldAny(inputPort, knowPorts...) {
				// if inputPort is empty or a know port of other protocol
				// return given defaultPort
				return call.Argument(1)
			}
			return call.Argument(0)
		},
	})

	// is port open check is port is actually open
	// it can be invoked as isPortOpen(host, port, [timeout])
	// where timeout is optional and defaults to 5 seconds
	_ = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "isPortOpen",
		Signatures: []string{
			"isPortOpen(host string, port string, [timeout int]) bool",
		},
		Description: "isPortOpen checks if given TCP port is open on host. timeout is optional and defaults to 5 seconds",
		FuncDecl: func(host string, port string, timeout ...int) (bool, error) {
			ctx := context.Background()
			if len(timeout) > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout[0])*time.Second)
				defer cancel()
			}
			if host == "" || port == "" {
				return false, errkit.New("isPortOpen: host or port is empty")
			}
			conn, err := protocolstate.Dialer.Dial(ctx, "tcp", net.JoinHostPort(host, port))
			if err != nil {
				return false, err
			}
			_ = conn.Close()
			return true, nil
		},
	})

	_ = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "isUDPPortOpen",
		Signatures: []string{
			"isUDPPortOpen(host string, port string, [timeout int]) bool",
		},
		Description: "isUDPPortOpen checks if the given UDP port is open on the host. Timeout is optional and defaults to 5 seconds.",
		FuncDecl: func(host string, port string, timeout ...int) (bool, error) {
			ctx := context.Background()
			if len(timeout) > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout[0])*time.Second)
				defer cancel()
			}
			if host == "" || port == "" {
				return false, errkit.New("isPortOpen: host or port is empty")
			}
			conn, err := protocolstate.Dialer.Dial(ctx, "udp", net.JoinHostPort(host, port))
			if err != nil {
				return false, err
			}
			_ = conn.Close()
			return true, nil
		},
	})

	_ = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "ToBytes",
		Signatures: []string{
			"ToBytes(...interface{}) []byte",
		},
		Description: "ToBytes converts given input to byte slice",
		FuncDecl: func(call goja.FunctionCall) goja.Value {
			var buff bytes.Buffer
			allVars := []any{}
			for _, v := range call.Arguments {
				if v.Export() == nil {
					continue
				}
				if v.ExportType().Kind() == reflect.Slice {
					// convert []datatype to []interface{}
					// since it cannot be type asserted to []interface{} directly
					rfValue := reflect.ValueOf(v.Export())
					for i := 0; i < rfValue.Len(); i++ {
						allVars = append(allVars, rfValue.Index(i).Interface())
					}
				} else {
					allVars = append(allVars, v.Export())
				}
			}
			for _, v := range allVars {
				buff.WriteString(types.ToString(v))
			}
			return runtime.ToValue(buff.Bytes())
		},
	})

	_ = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "ToString",
		Signatures: []string{
			"ToString(...interface{}) string",
		},
		Description: "ToString converts given input to string",
		FuncDecl: func(call goja.FunctionCall) goja.Value {
			var buff bytes.Buffer
			for _, v := range call.Arguments {
				exported := v.Export()
				if exported != nil {
					buff.WriteString(types.ToString(exported))
				}
			}
			return runtime.ToValue(buff.String())
		},
	})

	// register additional helpers
	registerAdditionalHelpers(runtime)
}

// RegisterNativeScripts are js scripts that were added for convenience
// and abstraction purposes we execute them in every runtime and make them
// available for use in any js script
// see: scripts/ for examples
func RegisterNativeScripts(runtime *goja.Runtime) error {
	initBuiltInFunc(runtime)

	dirs, err := embedFS.ReadDir("js")
	if err != nil {
		return err
	}
	for _, dir := range dirs {
		if dir.IsDir() {
			continue
		}
		// embeds have / as path separator (on all os)
		contents, err := embedFS.ReadFile("js" + "/" + dir.Name())
		if err != nil {
			return err
		}
		// run all built in js helper functions or scripts
		_, err = runtime.RunString(string(contents))
		if err != nil {
			return err
		}
	}
	// exports defines the exports object
	_, err = runtime.RunString(exports)
	if err != nil {
		return err
	}

	// import default modules
	_, err = runtime.RunString(defaultImports)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not import default modules %v", defaultImports)
	}

	return nil
}
