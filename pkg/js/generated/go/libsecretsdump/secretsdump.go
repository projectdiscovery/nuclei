package secretsdump

import (
	lib_secretsdump "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/secretsdump"

	"github.com/Mzack9999/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/secretsdump")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Objects / Classes
			"Client": lib_secretsdump.NewClient,
			"Secret": gojs.GetClassConstructor[lib_secretsdump.Secret](&lib_secretsdump.Secret{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
