package utils

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// FillPreviousEvent is a helper function to get the previous event from the event
// without leading to duplicate prefixes
func FillPreviousEvent(reqID string, event *output.InternalWrappedEvent, previous *mapsutil.SyncLockMap[string, any]) {
	if reqID == "" {
		return
	}

	for k, v := range event.InternalEvent {
		if _, ok := previous.Get(k); ok {
			continue
		}

		if strings.HasPrefix(k, reqID+"_") {
			continue
		}

		var builder strings.Builder

		builder.WriteString(reqID)
		builder.WriteString("_")
		builder.WriteString(k)

		_ = previous.Set(builder.String(), v)
	}
}
