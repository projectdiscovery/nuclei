package mssql

import (
	original_mssql "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/mssql"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/libmssql")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"Client": func() original_mssql.Client { return original_mssql.Client{} },

			// Types (pointer type)
			"NewClient": func() *original_mssql.Client { return &original_mssql.Client{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
