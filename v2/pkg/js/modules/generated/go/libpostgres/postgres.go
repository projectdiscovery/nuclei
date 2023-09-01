package postgres

import (
	lib_postgres "github.com/projectdiscovery/nuclei/v2/pkg/js/modules/libs/postgres"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/modules/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/postgres")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"Client": func() lib_postgres.Client { return lib_postgres.Client{} },

			// Types (pointer type)
			"NewClient": func() *lib_postgres.Client { return &lib_postgres.Client{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
