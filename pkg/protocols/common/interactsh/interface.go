package interactsh

import "regexp"

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
}
