package global

import (
	"encoding/base64"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

func registerAdditionalHelpers(runtime *goja.Runtime) {
	_ = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "atob",
		Signatures: []string{
			"atob(string) string",
		},
		Description: "Base64 decodes a given string",
		FuncDecl: func(call goja.FunctionCall) goja.Value {
			input := call.Argument(0).String()

			decoded, err := base64.StdEncoding.DecodeString(input)
			if err != nil {
				return goja.Null()
			}
			return runtime.ToValue(string(decoded))
		},
	})

	_ = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "btoa",
		Signatures: []string{
			"bota(string) string",
		},
		Description: "Base64 encodes a given string",
		FuncDecl: func(call goja.FunctionCall) goja.Value {
			input := call.Argument(0).String()
			encoded := base64.StdEncoding.EncodeToString([]byte(input))
			return runtime.ToValue(encoded)
		},
	})
}
