package ikev2

import (
	lib_ikev2 "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/ikev2"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/ikev2")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts
			"IKE_EXCHANGE_AUTH":             lib_ikev2.IKE_EXCHANGE_AUTH,
			"IKE_EXCHANGE_CREATE_CHILD_SA":  lib_ikev2.IKE_EXCHANGE_CREATE_CHILD_SA,
			"IKE_EXCHANGE_INFORMATIONAL":    lib_ikev2.IKE_EXCHANGE_INFORMATIONAL,
			"IKE_EXCHANGE_SA_INIT":          lib_ikev2.IKE_EXCHANGE_SA_INIT,
			"IKE_FLAGS_InitiatorBitCheck":   lib_ikev2.IKE_FLAGS_InitiatorBitCheck,
			"IKE_NOTIFY_NO_PROPOSAL_CHOSEN": lib_ikev2.IKE_NOTIFY_NO_PROPOSAL_CHOSEN,
			"IKE_NOTIFY_USE_TRANSPORT_MODE": lib_ikev2.IKE_NOTIFY_USE_TRANSPORT_MODE,
			"IKE_VERSION_2":                 lib_ikev2.IKE_VERSION_2,

			// Objects / Classes
			"IKEMessage":      gojs.GetClassConstructor[lib_ikev2.IKEMessage](&lib_ikev2.IKEMessage{}),
			"IKENonce":        gojs.GetClassConstructor[lib_ikev2.IKENonce](&lib_ikev2.IKENonce{}),
			"IKENotification": gojs.GetClassConstructor[lib_ikev2.IKENotification](&lib_ikev2.IKENotification{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
