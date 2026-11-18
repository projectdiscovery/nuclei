package ipmi

import (
	lib_ipmi "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/ipmi"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/ipmi")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"CheckRAKPPassword":   lib_ipmi.CheckRAKPPassword,
			"FindRAKPPassword":    lib_ipmi.FindRAKPPassword,
			"GetAuthCapabilities": lib_ipmi.GetAuthCapabilities,
			"GetCipherSuites":     lib_ipmi.GetCipherSuites,
			"GetRAKPHash":         lib_ipmi.GetRAKPHash,
			"GetSystemGUID":       lib_ipmi.GetSystemGUID,
			"Ping":                lib_ipmi.Ping,

			// Var and consts

			// Objects / Classes
			"AuthCapabilities": gojs.GetClassConstructor[lib_ipmi.AuthCapabilities](&lib_ipmi.AuthCapabilities{}),
			"Client":           gojs.GetClassConstructor[lib_ipmi.Client](&lib_ipmi.Client{}),
			"CommandResponse":  gojs.GetClassConstructor[lib_ipmi.CommandResponse](&lib_ipmi.CommandResponse{}),
			"RAKPHash":         gojs.GetClassConstructor[lib_ipmi.RAKPHash](&lib_ipmi.RAKPHash{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
