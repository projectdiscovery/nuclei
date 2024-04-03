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

func init() {
	// these are dummy functions we use trigger documentation generation
	// actual definations are in exports.js
	_ = gojs.RegisterFuncWithSignature(nil, gojs.FuncOpts{
		Name: "to_json",
		Signatures: []string{
			"to_json(any) object",
		},
		Description: "Converts a given object to JSON",
	})

	_ = gojs.RegisterFuncWithSignature(nil, gojs.FuncOpts{
		Name: "dump_json",
		Signatures: []string{
			"dump_json(any)",
		},
		Description: "Prints a given object as JSON in console",
	})

	_ = gojs.RegisterFuncWithSignature(nil, gojs.FuncOpts{
		Name: "to_array",
		Signatures: []string{
			"to_array(any) array",
		},
		Description: "Sets/Updates objects prototype to array to enable Array.XXX functions",
	})

	_ = gojs.RegisterFuncWithSignature(nil, gojs.FuncOpts{
		Name: "hex_to_ascii",
		Signatures: []string{
			"hex_to_ascii(string) string",
		},
		Description: "Converts a given hex string to ascii",
	})

}
