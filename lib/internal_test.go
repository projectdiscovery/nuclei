package nuclei

import "github.com/projectdiscovery/nuclei/v3/pkg/reporting"

// reportingOptionsForTest exposes the engine's parsed reporting.Options for
// tests in this package. Same-package access only — kept in a _test.go file
// so it is not part of the public SDK surface.
func (e *NucleiEngine) reportingOptionsForTest() *reporting.Options {
	return e.reportingOpts
}
