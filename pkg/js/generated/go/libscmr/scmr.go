package scmr

import (
	lib_scmr "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/scmr"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/scmr")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"NewClient": lib_scmr.NewClient,

			// Var and consts
			"Auth": lib_scmr.Auth,

			// Objects / Classes
			"Client": lib_scmr.NewClient,
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
