package utils

import (
	"regexp"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

var (
	reqTypeWithIndexRegex = regexp.MustCompile(`^(?:dns|http|headless|tcp|ssl|websocket|whois|code|javascript)_\d+_`)
)

// FillPreviousEvent is a helper function to get the previous event from the event
// without leading to duplicate prefixes
func FillPreviousEvent(ID string, event *output.InternalWrappedEvent, previous *mapsutil.SyncLockMap[string, any]) {
	if ID == "" {
		return
	}

	builder := &strings.Builder{}
	for k, v := range event.InternalEvent {
		if reqTypeWithIndexRegex.MatchString(k) {
			_ = previous.Set(k, v)
			continue
		}
		builder.WriteString(ID)
		builder.WriteString("_")
		builder.WriteString(k)
		_ = previous.Set(builder.String(), v)
		builder.Reset()
	}
}
