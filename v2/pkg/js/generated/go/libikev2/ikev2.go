package ikev2

import (
	original_ikev2 "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/ikev2"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/libikev2")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts
			"IKE_EXCHANGE_AUTH":             original_ikev2.IKE_EXCHANGE_AUTH,
			"IKE_EXCHANGE_CREATE_CHILD_SA":  original_ikev2.IKE_EXCHANGE_CREATE_CHILD_SA,
			"IKE_EXCHANGE_INFORMATIONAL":    original_ikev2.IKE_EXCHANGE_INFORMATIONAL,
			"IKE_EXCHANGE_SA_INIT":          original_ikev2.IKE_EXCHANGE_SA_INIT,
			"IKE_FLAGS_InitiatorBitCheck":   original_ikev2.IKE_FLAGS_InitiatorBitCheck,
			"IKE_NOTIFY_NO_PROPOSAL_CHOSEN": original_ikev2.IKE_NOTIFY_NO_PROPOSAL_CHOSEN,
			"IKE_NOTIFY_USE_TRANSPORT_MODE": original_ikev2.IKE_NOTIFY_USE_TRANSPORT_MODE,
			"IKE_VERSION_2":                 original_ikev2.IKE_VERSION_2,

			// Types (value type)
			"IKEMessage":      func() original_ikev2.IKEMessage { return original_ikev2.IKEMessage{} },
			"IKENonce":        func() original_ikev2.IKENonce { return original_ikev2.IKENonce{} },
			"IKENotification": func() original_ikev2.IKENotification { return original_ikev2.IKENotification{} },

			// Types (pointer type)
			"NewIKEMessage":      func() *original_ikev2.IKEMessage { return &original_ikev2.IKEMessage{} },
			"NewIKENonce":        func() *original_ikev2.IKENonce { return &original_ikev2.IKENonce{} },
			"NewIKENotification": func() *original_ikev2.IKENotification { return &original_ikev2.IKENotification{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
