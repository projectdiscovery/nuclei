package mssql

import (
	lib_mssql "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/mssql"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
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
			"MSSQLClient": func() lib_mssql.MSSQLClient { return lib_mssql.MSSQLClient{} },

			// Types (pointer type)
			"NewMSSQLClient": func() *lib_mssql.MSSQLClient { return &lib_mssql.MSSQLClient{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
