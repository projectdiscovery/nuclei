package smb

import (
	original_smb "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/smb"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/libsmb")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"Client": func() original_smb.Client { return original_smb.Client{} },

			// Types (pointer type)
			"NewClient": func() *original_smb.Client { return &original_smb.Client{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
