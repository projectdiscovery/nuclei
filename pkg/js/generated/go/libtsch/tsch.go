package tsch

import (
	lib_tsch "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/tsch"

	"github.com/Mzack9999/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/tsch")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"NewClient": lib_tsch.NewClient,

			// Var and consts
			"Auth": lib_tsch.Auth,

			// Objects / Classes
			"Client": lib_tsch.NewClient,
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
