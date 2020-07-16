package executor

import (
	"net/url"

	"github.com/asaskevich/govalidator"
)

// isURL tests a string to determine if it is a well-structured url or not.
func isURL(toTest string) bool {
	_, err := url.ParseRequestURI(toTest)
	if err != nil {
		return false
	}

	u, err := url.Parse(toTest)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	return true
}

// extractDomain extracts the domain name of a URL
func extractDomain(URL string) string {
	u, err := url.Parse(URL)
	if err != nil {
		return ""
	}
	hostname := u.Hostname()
	return hostname
}

// isDNS tests a string to determine if it is a well-structured dns or not
// even if it's oneliner, we leave it wrapped in a function call for
// future improvements
func isDNS(toTest string) bool {
	return govalidator.IsDNSName(toTest)
}
