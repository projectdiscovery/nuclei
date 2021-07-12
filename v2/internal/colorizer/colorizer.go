package colorizer

import (
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
)

const (
	fgOrange uint8 = 208
)

func GetColor(colorizer aurora.Aurora, severity goflags.Severity) string {
	var method func(arg interface{}) aurora.Value
	switch severity {
	case goflags.Info:
		method = colorizer.Blue
	case goflags.Low:
		method = colorizer.Green
	case goflags.Medium:
		method = colorizer.Yellow
	case goflags.High:
		method = func(stringValue interface{}) aurora.Value { return colorizer.Index(fgOrange, stringValue) }
	case goflags.Critical:
		method = colorizer.Red
	default:
		gologger.Warning().Msgf("The '%s' severity does not have an color associated!", severity)
		method = colorizer.White
	}

	return method(severity.String()).String()
}

func New(aurora aurora.Aurora) func(goflags.Severity) string {
	return func(severity goflags.Severity) string {
		return GetColor(aurora, severity)
	}
}
