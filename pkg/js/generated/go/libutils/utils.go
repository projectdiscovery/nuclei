package utils

import (
	lib_utils "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/utils"

	"github.com/Mzack9999/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/utils")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Objects / Classes
			"Utils": gojs.GetClassConstructor[lib_utils.Utils](&lib_utils.Utils{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
