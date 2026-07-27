package http

import (
	lib_http "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/http"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/http")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"DecodeNTLM":    lib_http.DecodeNTLM,
			"Get":           lib_http.Get,
			"Head":          lib_http.Head,
			"NegotiateNTLM": lib_http.NegotiateNTLM,
			"NewClient":     lib_http.NewClient,
			"Post":          lib_http.Post,
			"Request":       lib_http.Request,

			// Var and consts

			// Objects / Classes
			"Client":   lib_http.NewClient,
			"NTLMInfo": gojs.GetClassConstructor[lib_http.NTLMInfo](&lib_http.NTLMInfo{}),
			"Options":  gojs.GetClassConstructor[lib_http.Options](&lib_http.Options{}),
			"Response": gojs.GetClassConstructor[lib_http.Response](&lib_http.Response{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
