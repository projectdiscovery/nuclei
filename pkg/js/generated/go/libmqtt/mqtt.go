package mqtt

import (
	lib_mqtt "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/mqtt"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/mqtt")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"IsMQTT":             lib_mqtt.IsMQTT,
			"IsAnonymousAllowed": lib_mqtt.IsAnonymousAllowed,

			// Var and consts

			// Objects / Classes
			"Client":         gojs.GetClassConstructor[lib_mqtt.Client](&lib_mqtt.Client{}),
			"ConnectOptions": gojs.GetClassConstructor[lib_mqtt.ConnectOptions](&lib_mqtt.ConnectOptions{}),
			"ConnectResult":  gojs.GetClassConstructor[lib_mqtt.ConnectResult](&lib_mqtt.ConnectResult{}),
			"Message":        gojs.GetClassConstructor[lib_mqtt.Message](&lib_mqtt.Message{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
