package pop3

import (
	lib_pop3 "github.com/projectdiscovery/nuclei/v2/pkg/js/modules/libs/pop3"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/modules/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/pop3")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"Client":         func() lib_pop3.Client { return lib_pop3.Client{} },
			"IsPOP3Response": func() lib_pop3.IsPOP3Response { return lib_pop3.IsPOP3Response{} },

			// Types (pointer type)
			"NewClient":         func() *lib_pop3.Client { return &lib_pop3.Client{} },
			"NewIsPOP3Response": func() *lib_pop3.IsPOP3Response { return &lib_pop3.IsPOP3Response{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
