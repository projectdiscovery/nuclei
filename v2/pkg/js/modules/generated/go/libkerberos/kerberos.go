package kerberos

import (
	lib_kerberos "github.com/projectdiscovery/nuclei/v2/pkg/js/modules/libs/kerberos"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/modules/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/kerberos")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"Client":                func() lib_kerberos.Client { return lib_kerberos.Client{} },
			"EnumerateUserResponse": func() lib_kerberos.EnumerateUserResponse { return lib_kerberos.EnumerateUserResponse{} },

			// Types (pointer type)
			"NewClient":                func() *lib_kerberos.Client { return &lib_kerberos.Client{} },
			"NewEnumerateUserResponse": func() *lib_kerberos.EnumerateUserResponse { return &lib_kerberos.EnumerateUserResponse{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
