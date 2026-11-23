package utils

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"errors"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
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

// HasOfflineHTTPResponse reports whether this input already carries a response
// body for offline/passive HTTP matching (e.g. burp/jsonl/yaml exports).
// When true, InputHelper filepath transforms must be skipped so URL-shaped
// MetaInput.Input values are not discarded.
func HasOfflineHTTPResponse(meta *contextargs.MetaInput, proto templateTypes.ProtocolType) bool {
	if meta == nil || proto != templateTypes.OfflineHTTPProtocol {
		return false
	}
	rr := meta.ReqResp
	return rr != nil && rr.Response != nil && strings.TrimSpace(rr.Response.Raw) != ""
}

// LogRequestError logs the error of a request on the scan and warns about it.
// The executers return nil for it, so the engine has no error to warn about.
// A skip for an unresponsive address gets no warning, like the engine's own
// skip of a target.
func LogRequestError(ctx *scan.ScanContext, templateID string, err error) {
	ctx.LogError(err)

	if errors.Is(err, hosterrorscache.ErrUnresponsiveHost) {
		return
	}

	gologger.Warning().Msgf("[%s] Could not execute request for %s: %s\n",
		templateID, ctx.Input.MetaInput.PrettyPrint(), err)
}
