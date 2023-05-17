package kerberos

import (
	original_kerberos "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/kerberos"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/libkerberos")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"Client":                func() original_kerberos.Client { return original_kerberos.Client{} },
			"EnumerateUserResponse": func() original_kerberos.EnumerateUserResponse { return original_kerberos.EnumerateUserResponse{} },

			// Types (pointer type)
			"NewClient":                func() *original_kerberos.Client { return &original_kerberos.Client{} },
			"NewEnumerateUserResponse": func() *original_kerberos.EnumerateUserResponse { return &original_kerberos.EnumerateUserResponse{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
