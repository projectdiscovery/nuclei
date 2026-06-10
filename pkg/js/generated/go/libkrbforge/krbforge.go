package krbforge

import (
	lib_krbforge "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/krbforge"

	"github.com/Mzack9999/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/krbforge")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"CreateGoldenTicket": lib_krbforge.CreateGoldenTicket,
			"CreateSilverTicket": lib_krbforge.CreateSilverTicket,

			// Var and consts

			// Objects / Classes
			"Ticket":        gojs.GetClassConstructor[lib_krbforge.Ticket](&lib_krbforge.Ticket{}),
			"TicketRequest": gojs.GetClassConstructor[lib_krbforge.TicketRequest](&lib_krbforge.TicketRequest{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
