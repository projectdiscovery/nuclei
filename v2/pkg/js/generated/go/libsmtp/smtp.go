package smtp

import (
	original_smtp "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/smtp"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/libsmtp")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"Client":         func() original_smtp.Client { return original_smtp.Client{} },
			"IsSMTPResponse": func() original_smtp.IsSMTPResponse { return original_smtp.IsSMTPResponse{} },

			// Types (pointer type)
			"NewClient":         func() *original_smtp.Client { return &original_smtp.Client{} },
			"NewIsSMTPResponse": func() *original_smtp.IsSMTPResponse { return &original_smtp.IsSMTPResponse{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
