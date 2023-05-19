package compiler

import (
	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/console"
	"github.com/dop251/goja_nodejs/require"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/scripts"
)

// registerHelpersForVM registers all the helper functions for the goja runtime.
func (c *Compiler) registerHelpersForVM(runtime *goja.Runtime) {
	_ = c.registry.Enable(runtime)
	runtime.Set("console", require.Require(runtime, console.ModuleName))

	// Register embedded scripts
	if err := scripts.RegisterNativeScripts(runtime); err != nil {
		gologger.Error().Msgf("Could not register scripts: %s\n", err)
	}
}
