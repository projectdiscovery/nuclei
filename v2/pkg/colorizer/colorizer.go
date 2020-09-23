package colorizer

import (
	"strings"

	"github.com/logrusorgru/aurora"
)

const (
	fgOrange  uint8  = 208
	undefined string = "undefined"
)

// NucleiColorizer contains the severity color mapping
type NucleiColorizer struct {
	Colorizer   aurora.Aurora
	SeverityMap map[string]string
}

// NewNucleiColorizer initializes the new nuclei colorizer
func NewNucleiColorizer(colorizer aurora.Aurora) *NucleiColorizer {
	return &NucleiColorizer{
		Colorizer: colorizer,
		SeverityMap: map[string]string{
			"info":     colorizer.Blue("info").String(),
			"low":      colorizer.Green("low").String(),
			"medium":   colorizer.Yellow("medium").String(),
			"high":     colorizer.Index(fgOrange, "high").String(),
			"critical": colorizer.Red("critical").String(),
		},
	}
}

// GetColorizedSeverity returns the colorized severity string
func (r *NucleiColorizer) GetColorizedSeverity(severity string) string {
	sev := r.SeverityMap[strings.ToLower(severity)]
	if sev == "" {
		return undefined
	}

	return sev
}
