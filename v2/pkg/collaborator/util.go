package collaborator

import (
	"github.com/projectdiscovery/collaborator"
)

func removeMatch(responses []collaborator.BurpResponse, index int) []collaborator.BurpResponse {
	return append(responses[:index], responses[index+1:]...)
}
