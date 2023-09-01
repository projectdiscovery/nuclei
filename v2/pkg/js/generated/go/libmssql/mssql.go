package mssql

import (
	lib_mssql "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/mssql"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/mssql")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"Client": func() lib_mssql.Client { return lib_mssql.Client{} },

			// Types (pointer type)
			"NewClient": func() *lib_mssql.Client { return &lib_mssql.Client{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
