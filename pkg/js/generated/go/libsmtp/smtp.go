package smtp

import (
	lib_smtp "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/smtp"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
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
			"IsSMTPResponse": func() lib_smtp.IsSMTPResponse { return lib_smtp.IsSMTPResponse{} },
			"SMTPClient":     func() lib_smtp.SMTPClient { return lib_smtp.SMTPClient{} },

			// Types (pointer type)
			"NewIsSMTPResponse": func() *lib_smtp.IsSMTPResponse { return &lib_smtp.IsSMTPResponse{} },
			"NewSMTPClient":     func() *lib_smtp.SMTPClient { return &lib_smtp.SMTPClient{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
