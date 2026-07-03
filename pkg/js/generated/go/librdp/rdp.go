package rdp

import (
	lib_rdp "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/rdp"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/rdp")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"CheckRDPAuth":       lib_rdp.CheckRDPAuth,
			"CheckRDPEncryption": lib_rdp.CheckRDPEncryption,
			"IsRDP":              lib_rdp.IsRDP,

			// Var and consts
			"EncryptionLevelFIPS140_1":              lib_rdp.EncryptionLevelFIPS140_1,
			"EncryptionLevelRC4_128bit":             lib_rdp.EncryptionLevelRC4_128bit,
			"EncryptionLevelRC4_40bit":              lib_rdp.EncryptionLevelRC4_40bit,
			"EncryptionLevelRC4_56bit":              lib_rdp.EncryptionLevelRC4_56bit,
			"SecurityLayerCredSSP":                  lib_rdp.SecurityLayerCredSSP,
			"SecurityLayerCredSSPWithEarlyUserAuth": lib_rdp.SecurityLayerCredSSPWithEarlyUserAuth,
			"SecurityLayerNativeRDP":                lib_rdp.SecurityLayerNativeRDP,
			"SecurityLayerRDSTLS":                   lib_rdp.SecurityLayerRDSTLS,
			"SecurityLayerSSL":                      lib_rdp.SecurityLayerSSL,

			// Objects / Classes
			"CheckRDPAuthResponse":  gojs.GetClassConstructor[lib_rdp.CheckRDPAuthResponse](&lib_rdp.CheckRDPAuthResponse{}),
			"IsRDPResponse":         gojs.GetClassConstructor[lib_rdp.IsRDPResponse](&lib_rdp.IsRDPResponse{}),
			"RDPEncryptionResponse": gojs.GetClassConstructor[lib_rdp.RDPEncryptionResponse](&lib_rdp.RDPEncryptionResponse{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
