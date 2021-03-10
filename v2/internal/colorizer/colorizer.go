package colorizer

import "github.com/logrusorgru/aurora"

// Colorizer returns a colorized severity printer
type Colorizer struct {
	Data map[string]string
}

const (
	fgOrange uint8 = 208
)

// New returns a new severity based colorizer
func New(colorizer aurora.Aurora) *Colorizer {
	severityMap := map[string]string{
		"info":     colorizer.Blue("info").String(),
		"low":      colorizer.Green("low").String(),
		"medium":   colorizer.Yellow("medium").String(),
		"high":     colorizer.Index(fgOrange, "high").String(),
		"critical": colorizer.Red("critical").String(),
	}
	return &Colorizer{Data: severityMap}
}
