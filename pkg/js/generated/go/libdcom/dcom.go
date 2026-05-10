package dcom

import (
	lib_dcom "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/dcom"

	"github.com/Mzack9999/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/dcom")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"NewClient": lib_dcom.NewClient,

			// Var and consts
			"Auth": lib_dcom.Auth,

			// Objects / Classes
			"Client": lib_dcom.NewClient,
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
