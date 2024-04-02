package compiler

import (
	"github.com/dop251/goja_nodejs/console"
	"github.com/dop251/goja_nodejs/require"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/libs/goconsole"
)

var r *require.Registry

func init() {
	r = new(require.Registry) // this can be shared by multiple runtimes
	// autoregister console node module with default printer it uses gologger backend
	require.RegisterNativeModule(console.ModuleName, console.RequireWithPrinter(goconsole.NewGoConsolePrinter()))
}
