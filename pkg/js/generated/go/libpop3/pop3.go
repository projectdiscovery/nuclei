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

			// Var and consts

			// Types (value type)
			"IsPOP3Response": func() lib_pop3.IsPOP3Response { return lib_pop3.IsPOP3Response{} },
			"Pop3Client":     func() lib_pop3.Pop3Client { return lib_pop3.Pop3Client{} },

			// Types (pointer type)
			"NewIsPOP3Response": func() *lib_pop3.IsPOP3Response { return &lib_pop3.IsPOP3Response{} },
			"NewPop3Client":     func() *lib_pop3.Pop3Client { return &lib_pop3.Pop3Client{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
