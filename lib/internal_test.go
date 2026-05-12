package nuclei

import "github.com/projectdiscovery/nuclei/v3/pkg/reporting"

// reportingOptionsForTest exposes e.reportingOpts to same-package tests.
// In a _test.go file so it stays off the public SDK surface.
func (e *NucleiEngine) reportingOptionsForTest() *reporting.Options {
	return e.reportingOpts
}
