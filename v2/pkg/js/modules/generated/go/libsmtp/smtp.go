package smtp

import (
	lib_smtp "github.com/projectdiscovery/nuclei/v2/pkg/js/modules/libs/smtp"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/modules/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/smtp")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"Client":         func() lib_smtp.Client { return lib_smtp.Client{} },
			"IsSMTPResponse": func() lib_smtp.IsSMTPResponse { return lib_smtp.IsSMTPResponse{} },

			// Types (pointer type)
			"NewClient":         func() *lib_smtp.Client { return &lib_smtp.Client{} },
			"NewIsSMTPResponse": func() *lib_smtp.IsSMTPResponse { return &lib_smtp.IsSMTPResponse{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
