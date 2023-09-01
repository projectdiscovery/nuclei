package ssh

import (
	lib_ssh "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/ssh"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/ssh")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"Client": func() lib_ssh.Client { return lib_ssh.Client{} },

			// Types (pointer type)
			"NewClient": func() *lib_ssh.Client { return &lib_ssh.Client{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
