package smb

import (
	lib_smb "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/smb"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/smb")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Objects / Classes
			"SMBClient": gojs.GetClassConstructor[lib_smb.SMBClient](&lib_smb.SMBClient{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
