package interactsh

import (
	"regexp"

	"github.com/projectdiscovery/interactsh/pkg/server"
)

type IClient interface {
	AlreadyMatched(data *RequestData) bool
	URL() (string, error)
	Close() bool
	Replace(data string, interactshURLs []string) (string, []string)
	ReplaceWithMarker(data string, regex *regexp.Regexp, interactshURLs []string) (string, []string)
	NewURL() (string, error)
	NewURLWithData(data string) (string, error)
	MakePlaceholders(urls []string, data map[string]interface{})
	RequestEvent(interactshURLs []string, data *RequestData)
	GetHostname() string
	SetInteractionCallback(cb func(interaction *server.Interaction, foundRequest *RequestData))
	NewRequestScope() *RequestScope
}
