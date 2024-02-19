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

			// Objects / Classes
			"IsSMTPResponse": gojs.GetClassConstructor[lib_smtp.IsSMTPResponse](&lib_smtp.IsSMTPResponse{}),
			"SMTPClient":     gojs.GetClassConstructor[lib_smtp.SMTPClient](&lib_smtp.SMTPClient{}),
			"SMTPMessage":    gojs.GetClassConstructor[lib_smtp.SMTPMessage](&lib_smtp.SMTPMessage{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
