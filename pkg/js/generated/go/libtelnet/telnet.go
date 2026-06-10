package telnet

import (
	lib_telnet "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/telnet"

	"github.com/Mzack9999/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/telnet")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"IsTelnet": lib_telnet.IsTelnet,

			// Var and consts
			"DO":                lib_telnet.DO,
			"DONT":              lib_telnet.DONT,
			"ECHO":              lib_telnet.ECHO,
			"ENCRYPT":           lib_telnet.ENCRYPT,
			"IAC":               lib_telnet.IAC,
			"NAWS":              lib_telnet.NAWS,
			"SB":                lib_telnet.SB,
			"SE":                lib_telnet.SE,
			"SUPPRESS_GO_AHEAD": lib_telnet.SUPPRESS_GO_AHEAD,
			"TERMINAL_TYPE":     lib_telnet.TERMINAL_TYPE,
			"WILL":              lib_telnet.WILL,
			"WONT":              lib_telnet.WONT,

			// Objects / Classes
			"IsTelnetResponse":   gojs.GetClassConstructor[lib_telnet.IsTelnetResponse](&lib_telnet.IsTelnetResponse{}),
			"TelnetClient":       gojs.GetClassConstructor[lib_telnet.TelnetClient](&lib_telnet.TelnetClient{}),
			"TelnetInfoResponse": gojs.GetClassConstructor[lib_telnet.TelnetInfoResponse](&lib_telnet.TelnetInfoResponse{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
