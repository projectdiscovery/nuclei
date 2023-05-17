package rdp

import (
	original_rdp "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/rdp"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/librdp")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"CheckRDPAuthResponse": func() original_rdp.CheckRDPAuthResponse { return original_rdp.CheckRDPAuthResponse{} },
			"Client":               func() original_rdp.Client { return original_rdp.Client{} },
			"IsRDPResponse":        func() original_rdp.IsRDPResponse { return original_rdp.IsRDPResponse{} },

			// Types (pointer type)
			"NewCheckRDPAuthResponse": func() *original_rdp.CheckRDPAuthResponse { return &original_rdp.CheckRDPAuthResponse{} },
			"NewClient":               func() *original_rdp.Client { return &original_rdp.Client{} },
			"NewIsRDPResponse":        func() *original_rdp.IsRDPResponse { return &original_rdp.IsRDPResponse{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
