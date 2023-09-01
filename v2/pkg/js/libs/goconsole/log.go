package goconsole

import (
	"github.com/dop251/goja_nodejs/console"
	"github.com/projectdiscovery/gologger"
)

var _ console.Printer = &GoConsolePrinter{}

// GoConsolePrinter is a console printer for nuclei using gologger
type GoConsolePrinter struct {
	logger *gologger.Logger
}

func NewGoConsolePrinter() *GoConsolePrinter {
	return &GoConsolePrinter{
		logger: gologger.DefaultLogger,
	}
}

func (p *GoConsolePrinter) Log(msg string) {
	p.logger.Info().Msg(msg)
}

func (p *GoConsolePrinter) Warn(msg string) {
	p.logger.Warning().Msg(msg)
}

func (p *GoConsolePrinter) Error(msg string) {
	p.logger.Error().Msg(msg)
}
