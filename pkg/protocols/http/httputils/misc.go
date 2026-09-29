package httputils

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// if template contains more than 1 request and matchers require requestcondition from
// both requests , then we need to request for event from interactsh even if current request
// doesnot use interactsh url in it
func GetInteractshURLSFromEvent(event map[string]interface{}) []string {
	interactshUrls := map[string]struct{}{}
	for k, v := range event {
		if strings.HasPrefix(k, "interactsh-url") {
			interactshUrls[types.ToString(v)] = struct{}{}
		}
	}
	return mapsutil.GetKeys(interactshUrls)
}
