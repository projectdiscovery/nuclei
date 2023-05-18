package pop3

import (
	original_pop3 "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/pop3"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/libpop3")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"Client":         func() original_pop3.Client { return original_pop3.Client{} },
			"IsPOP3Response": func() original_pop3.IsPOP3Response { return original_pop3.IsPOP3Response{} },

			// Types (pointer type)
			"NewClient":         func() *original_pop3.Client { return &original_pop3.Client{} },
			"NewIsPOP3Response": func() *original_pop3.IsPOP3Response { return &original_pop3.IsPOP3Response{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
