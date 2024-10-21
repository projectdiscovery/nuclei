package pop3

import (
	lib_pop3 "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/pop3"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/pop3")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"IsPOP3": lib_pop3.IsPOP3,

			// Var and consts

			// Objects / Classes
			"IsPOP3Response": gojs.GetClassConstructor[lib_pop3.IsPOP3Response](&lib_pop3.IsPOP3Response{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
