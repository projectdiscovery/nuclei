package dcerpc

import (
	"fmt"

	gpsrvsvc "github.com/Mzack9999/goimpacket/pkg/dcerpc/srvsvc"
	gpsvcctl "github.com/Mzack9999/goimpacket/pkg/dcerpc/svcctl"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// ServiceEntry is a flat SVCCTL service record suitable for JS templates
// (nmap smb-enum-services).
type ServiceEntry struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	State       string `json:"state"`
	StateCode   uint32 `json:"state_code"`
	Controls    uint32 `json:"controls,omitempty"`
}

// SessionEntry is a flat SRVSVC session record (nmap smb-enum-sessions).
type SessionEntry struct {
	Client   string `json:"client"`
	Username string `json:"username"`
	Active   uint32 `json:"active_seconds"`
	Idle     uint32 `json:"idle_seconds"`
}

// EnumServices lists Win32 services on the target via SVCCTL
// (nmap: smb-enum-services). Requires an authenticated session with rights
// to open the Service Control Manager.
//
// @example
// ```javascript
// const dcerpc = require('nuclei/dcerpc');
// const c = new dcerpc.Client('dc01.acme.local', 'acme.local', 'admin', 'P@ssw0rd');
// const services = c.EnumServices();
// for (const s of services) {
//   if (s.State === 'RUNNING') { log(s.Name + ' => ' + s.DisplayName); }
// }
// ```
func (c *Client) EnumServices() ([]ServiceEntry, error) {
	if !protocolstate.IsHostAllowed(c.nj.ExecutionId(), c.Host) {
		return nil, protocolstate.ErrHostDenied.Msgf(c.Host)
	}
	rpc, err := c.rpcOverNamedPipe("svcctl", gpsvcctl.UUID, gpsvcctl.MajorVersion, gpsvcctl.MinorVersion)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rpc.Transport.Close()
	}()

	sc, err := gpsvcctl.NewServiceController(rpc)
	if err != nil {
		return nil, fmt.Errorf("svcctl open scm: %w", err)
	}
	defer sc.Close()

	// SERVICE_WIN32 = OWN | SHARE; SERVICE_STATE_ALL = active + inactive
	const serviceWin32 = gpsvcctl.SERVICE_WIN32_OWN_PROCESS | gpsvcctl.SERVICE_WIN32_SHARE_PROCESS
	raw, err := sc.EnumServicesStatus(serviceWin32, gpsvcctl.SERVICE_STATE_ALL)
	if err != nil {
		return nil, err
	}
	return mapServiceEntries(raw), nil
}

// EnumSessions lists SMB sessions known to the server via SRVSVC
// (nmap: smb-enum-sessions). Often requires administrative rights.
//
// @example
// ```javascript
// const dcerpc = require('nuclei/dcerpc');
// const c = new dcerpc.Client('fs01.acme.local', 'acme.local', 'admin', 'P@ssw0rd');
// const sessions = c.EnumSessions();
// for (const s of sessions) {
//   log(s.Username + '@' + s.Client + ' active=' + s.Active + 's');
// }
// ```
func (c *Client) EnumSessions() ([]SessionEntry, error) {
	if !protocolstate.IsHostAllowed(c.nj.ExecutionId(), c.Host) {
		return nil, protocolstate.ErrHostDenied.Msgf(c.Host)
	}
	rpc, err := c.rpcOverNamedPipe("srvsvc", gpsrvsvc.UUID, gpsrvsvc.MajorVersion, gpsrvsvc.MinorVersion)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rpc.Transport.Close()
	}()

	raw, err := gpsrvsvc.NetrSessionEnum(rpc)
	if err != nil {
		return nil, err
	}
	return mapSessionEntries(raw), nil
}

func mapServiceEntries(raw []gpsvcctl.EnumServiceEntry) []ServiceEntry {
	out := make([]ServiceEntry, 0, len(raw))
	for _, e := range raw {
		out = append(out, ServiceEntry{
			Name:        e.ServiceName,
			DisplayName: e.DisplayName,
			State:       gpsvcctl.GetServiceState(e.Status.CurrentState),
			StateCode:   e.Status.CurrentState,
			Controls:    e.Status.ControlsAccepted,
		})
	}
	return out
}

func mapSessionEntries(raw []gpsrvsvc.SessionInfo10) []SessionEntry {
	out := make([]SessionEntry, 0, len(raw))
	for _, e := range raw {
		out = append(out, SessionEntry{
			Client:   e.Cname,
			Username: e.Username,
			Active:   e.ActiveTime,
			Idle:     e.IdleTime,
		})
	}
	return out
}
