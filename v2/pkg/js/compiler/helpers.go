package compiler

import (
	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/console"
	"github.com/dop251/goja_nodejs/require"
)

// registerHelpersForVM registers all the helper functions for the goja runtime.
func (c *Compiler) registerHelpersForVM(runtime *goja.Runtime) {
	_ = c.registry.Enable(runtime)
	runtime.Set("console", require.Require(runtime, console.ModuleName))
}
