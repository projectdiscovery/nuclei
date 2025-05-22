package protocolstate

import (
	"github.com/dop251/goja"
	"github.com/dop251/goja/parser"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/js"
)

// NewJSRuntime returns a new javascript runtime
// with defaults set
// i.e sourcemap parsing is disabled by default
func NewJSRuntime() *goja.Runtime {
	vm := goja.New()
	vm.SetParserOptions(parser.WithDisableSourceMaps)

	// disable eval by default
	if err := vm.Set("eval", "undefined"); err != nil {
		gologger.Error().Msgf("could not set eval to undefined: %s", err)
	}

	js.RegisterNodeModules(vm)

	return vm
}
