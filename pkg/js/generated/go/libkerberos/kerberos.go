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
			"ASRepToHashcat":              lib_kerberos.ASRepToHashcat,
			"CheckKrbError":               lib_kerberos.CheckKrbError,
			"NewKerberosClient":           lib_kerberos.NewKerberosClient,
			"NewKerberosClientFromString": lib_kerberos.NewKerberosClientFromString,
			"SendToKDC":                   lib_kerberos.SendToKDC,
			"TGStoHashcat":                lib_kerberos.TGStoHashcat,

			// Var and consts

			// Types (value type)
			"Client":                lib_kerberos.NewKerberosClient,
			"EnumerateUserResponse": func() lib_kerberos.EnumerateUserResponse { return lib_kerberos.EnumerateUserResponse{} },
			"TGS":                   func() lib_kerberos.TGS { return lib_kerberos.TGS{} },
			"Config":                func() lib_kerberos.Config { return lib_kerberos.Config{} },

			// Types (pointer type)
			// "NewClient":                func() *lib_kerberos.Client { return &lib_kerberos.Client{} },
			// "NewEnumerateUserResponse": func() *lib_kerberos.EnumerateUserResponse { return &lib_kerberos.EnumerateUserResponse{} },
			// "NewTGS":                   func() *lib_kerberos.TGS { return &lib_kerberos.TGS{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
