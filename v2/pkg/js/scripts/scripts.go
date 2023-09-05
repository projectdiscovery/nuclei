package scripts

import (
	"embed"
	"math/rand"
	"net"
	"time"

	"github.com/dop251/goja"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/scripts/gotypes/buffer"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/utils/vardump"
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

// initBuiltInFunc initializes runtime with builtin functions
func initBuiltInFunc(runtime *goja.Runtime) {
	module := buffer.Module{}
	module.Enable(runtime)

	_ = runtime.Set("Rand", func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(rand.Intn(255))
		}
		return b
	})
	_ = runtime.Set("RandInt", func() int64 {
		return rand.Int63()
	})
	_ = runtime.Set("log", func(call goja.FunctionCall) goja.Value {
		// TODO: verify string interpolation and handle multiple args
		arg := call.Argument(0).Export()
		switch value := arg.(type) {
		case string:
			gologger.DefaultLogger.Print().Msgf("[%v] %v", aurora.BrightCyan("JS"), value)
		case map[string]interface{}:
			gologger.DefaultLogger.Print().Msgf("[%v] %v", aurora.BrightCyan("JS"), vardump.DumpVariables(value))
		default:
			gologger.DefaultLogger.Print().Msgf("[%v] %v", aurora.BrightCyan("JS"), value)
		}
		return goja.Null()
	})
	// getNetworkPort returns the port if it is not a known port
	_ = runtime.Set("getNetworkPort", func(call goja.FunctionCall) goja.Value {
		inputPort := call.Argument(0).String()
		if inputPort == "" || stringsutil.EqualFoldAny(inputPort, knowPorts...) {
			// if inputPort is empty or a know port of other protocol
			// return given defaultPort
			return call.Argument(1)
		}
		return call.Argument(0)
	})

	// is port open check is port is actually open
	// it can be invoked as isPortOpen(host, port, [timeout])
	// where timeout is optional and defaults to 5 seconds
	_ = runtime.Set("isPortOpen", func(call goja.FunctionCall) goja.Value {
		host := call.Argument(0).String()
		if host == "" {
			return runtime.ToValue(false)
		}
		port := call.Argument(1).String()
		if port == "" {
			return runtime.ToValue(false)
		}
		timeoutinSec := call.Argument(2).ToInteger()
		if timeoutinSec == 0 {
			timeoutinSec = 5
		}
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), time.Duration(timeoutinSec)*time.Second)
		if err != nil {
			return runtime.ToValue(false)
		}
		_ = conn.Close()
		return runtime.ToValue(true)
	})
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
	return nil
}
