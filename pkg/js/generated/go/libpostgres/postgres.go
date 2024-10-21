package postgres

import (
	lib_postgres "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/postgres"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/postgres")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Objects / Classes
			"PGClient": gojs.GetClassConstructor[lib_postgres.PGClient](&lib_postgres.PGClient{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
