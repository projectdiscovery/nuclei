package layers

import (
	original_layers "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/layers"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/liblayers")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts
			"IKE_EXCHANGE_AUTH":             original_layers.IKE_EXCHANGE_AUTH,
			"IKE_EXCHANGE_CREATE_CHILD_SA":  original_layers.IKE_EXCHANGE_CREATE_CHILD_SA,
			"IKE_EXCHANGE_INFORMATIONAL":    original_layers.IKE_EXCHANGE_INFORMATIONAL,
			"IKE_EXCHANGE_SA_INIT":          original_layers.IKE_EXCHANGE_SA_INIT,
			"IKE_FLAGS_InitiatorBitCheck":   original_layers.IKE_FLAGS_InitiatorBitCheck,
			"IKE_NOTIFY_NO_PROPOSAL_CHOSEN": original_layers.IKE_NOTIFY_NO_PROPOSAL_CHOSEN,
			"IKE_NOTIFY_USE_TRANSPORT_MODE": original_layers.IKE_NOTIFY_USE_TRANSPORT_MODE,
			"IKE_VERSION_2":                 original_layers.IKE_VERSION_2,

			// Types (value type)
			"IKEMessage":      func() original_layers.IKEMessage { return original_layers.IKEMessage{} },
			"IKENonce":        func() original_layers.IKENonce { return original_layers.IKENonce{} },
			"IKENotification": func() original_layers.IKENotification { return original_layers.IKENotification{} },

			// Types (pointer type)
			"NewIKEMessage":      func() *original_layers.IKEMessage { return &original_layers.IKEMessage{} },
			"NewIKENonce":        func() *original_layers.IKENonce { return &original_layers.IKENonce{} },
			"NewIKENotification": func() *original_layers.IKENotification { return &original_layers.IKENotification{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
