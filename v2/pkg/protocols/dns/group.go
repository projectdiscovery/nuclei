package dns

import "github.com/projectdiscovery/nuclei/v2/pkg/protocols"

// Group is a group of requests to be executed for a protocol.
type Group []protocols.Executer

// Execute executes the group of protocol requests
func (g Group) Execute() {
	for _, executer := range g {
		executer.ExecuteWithResults()
	}
}
