package protocolstate

import (
	"github.com/Mzack9999/goja"
	"github.com/Mzack9999/goja/parser"
	"github.com/projectdiscovery/gologger"
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
	return vm
}
