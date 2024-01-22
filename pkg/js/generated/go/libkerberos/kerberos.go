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
			"Client": lib_kerberos.NewKerberosClient,

			// Var and consts

			// Types (value type)
			// "Client":                func() lib_kerberos.Client { return lib_kerberos.Client{} },
			"EnumerateUserResponse": func() lib_kerberos.EnumerateUserResponse { return lib_kerberos.EnumerateUserResponse{} },
			"KerberosClient":        func() lib_kerberos.KerberosClient { return lib_kerberos.KerberosClient{} },
			"ServiceOptions":        func() lib_kerberos.ServiceOptions { return lib_kerberos.ServiceOptions{} },
			"TGS":                   func() lib_kerberos.TGS { return lib_kerberos.TGS{} },

			// Types (pointer type)
			"NewClient":                func() *lib_kerberos.Client { return &lib_kerberos.Client{} },
			"NewEnumerateUserResponse": func() *lib_kerberos.EnumerateUserResponse { return &lib_kerberos.EnumerateUserResponse{} },
			"NewServiceOptions":        func() *lib_kerberos.ServiceOptions { return &lib_kerberos.ServiceOptions{} },
			"NewTGS":                   func() *lib_kerberos.TGS { return &lib_kerberos.TGS{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
