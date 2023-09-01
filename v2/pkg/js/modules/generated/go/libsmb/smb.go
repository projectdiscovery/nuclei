package smb

import (
	lib_smb "github.com/projectdiscovery/nuclei/v2/pkg/js/modules/libs/smb"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/modules/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/smb")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"Client": func() lib_smb.Client { return lib_smb.Client{} },

			// Types (pointer type)
			"NewClient": func() *lib_smb.Client { return &lib_smb.Client{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
