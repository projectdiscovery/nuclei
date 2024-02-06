package goconsole

import (
	lib_goconsole "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/goconsole"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/goconsole")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"NewGoConsolePrinter": lib_goconsole.NewGoConsolePrinter,

			// Var and consts

			// Objects / Classes
			"GoConsolePrinter": gojs.GetClassConstructor[lib_goconsole.GoConsolePrinter](&lib_goconsole.GoConsolePrinter{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
