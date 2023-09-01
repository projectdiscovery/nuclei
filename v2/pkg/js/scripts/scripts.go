package scripts

import (
	"embed"
	"fmt"
	"math/rand"
	"path/filepath"

	"github.com/dop251/goja"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/scripts/gotypes/buffer"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/utils/vardump"
)

var (
	//go:embed js
	embedFS embed.FS

	//go:embed exports.js
	exports string
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
	// export exports given values to nuclei
	_ = runtime.Set("exportToNuclei", func(call goja.FunctionCall) goja.Value {
		for _, v := range call.Arguments {
			fmt.Printf("%v\n", v.ExportType())
		}
		return goja.Null()
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
		contents, err := embedFS.ReadFile(filepath.Join("js", dir.Name()))
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
