package dcerpc

import (
	gptr "github.com/Mzack9999/goimpacket/pkg/transport"

	"github.com/projectdiscovery/nuclei/v3/pkg/js/libs/gptransport"
)

// NewExecDialer is kept on the dcerpc package for JS/bindgen compatibility and
// existing Go call sites (krbroast, secretsdump). Implementation lives in
// gptransport so smb / file / dcerpc share one dialer.
func NewExecDialer(execID string) *gptr.Dialer {
	return gptransport.NewExecDialer(execID)
}