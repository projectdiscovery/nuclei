package scanstrategy

import (
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// ScanStrategy supported
type ScanStrategy uint8

const (
	Auto ScanStrategy = iota
	HostSpray
	TemplateSpray
)

var strategies mapsutil.Map[ScanStrategy, string]

func init() {
	strategies = make(mapsutil.Map[ScanStrategy, string])
	strategies[Auto] = "auto"
	strategies[HostSpray] = "host-spray"
	strategies[TemplateSpray] = "template-spray"
}

// String representation of the scan strategy
func (s ScanStrategy) String() string {
	return strategies[s]
}
