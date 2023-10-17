package kerberos

import (
	lib_kerberos "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/kerberos"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
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
			"EnumerateUserResponse": func() lib_kerberos.EnumerateUserResponse { return lib_kerberos.EnumerateUserResponse{} },
			"KerberosClient":        func() lib_kerberos.KerberosClient { return lib_kerberos.KerberosClient{} },

			// Types (pointer type)
			"NewEnumerateUserResponse": func() *lib_kerberos.EnumerateUserResponse { return &lib_kerberos.EnumerateUserResponse{} },
			"NewKerberosClient":        func() *lib_kerberos.KerberosClient { return &lib_kerberos.KerberosClient{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
