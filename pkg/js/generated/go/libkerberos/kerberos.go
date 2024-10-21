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

			// Objects / Classes
			"Client":                lib_kerberos.NewKerberosClient,
			"Config":                gojs.GetClassConstructor[lib_kerberos.Config](&lib_kerberos.Config{}),
			"EnumerateUserResponse": gojs.GetClassConstructor[lib_kerberos.EnumerateUserResponse](&lib_kerberos.EnumerateUserResponse{}),
			"TGS":                   gojs.GetClassConstructor[lib_kerberos.TGS](&lib_kerberos.TGS{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
