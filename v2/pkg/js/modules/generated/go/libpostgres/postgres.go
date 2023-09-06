package postgres

import (
	lib_postgres "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/postgres"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
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
			"Client": func() lib_postgres.PGClient { return lib_postgres.PGClient{} },

			// Types (pointer type)
			"NewClient": func() *lib_postgres.PGClient { return &lib_postgres.PGClient{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
