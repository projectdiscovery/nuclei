package dcerpc

import (
	"fmt"

	gpsrvsvc "github.com/Mzack9999/goimpacket/pkg/dcerpc/srvsvc"
	gpsvcctl "github.com/Mzack9999/goimpacket/pkg/dcerpc/svcctl"
	winstation "github.com/Mzack9999/goimpacket/pkg/dcerpc/tsts"
	gpwkssvc "github.com/Mzack9999/goimpacket/pkg/dcerpc/wkssvc"
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

// ProcessEntry is a running process from the Terminal Services Legacy API
// (nmap smb-enum-processes analogue; nmap uses winreg perf counters, we use WinStation).
type ProcessEntry struct {
	Name           string `json:"name"`
	PID            uint32 `json:"pid"`
	SessionID      uint32 `json:"session_id"`
	WorkingSetSize uint32 `json:"working_set_size,omitempty"`
	SID            string `json:"sid,omitempty"`
}

// LoggedOnUser is a WKSSVC workstation user record (interactive / network logons
// known to the target). Useful companion to SamrEnumerateUsers / EnumSessions.
type LoggedOnUser struct {
	Username    string `json:"username"`
	LogonDomain string `json:"logon_domain"`
	OthDomains  string `json:"other_domains,omitempty"`
	LogonServer string `json:"logon_server,omitempty"`
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
//
//	for (const s of services) {
//	  if (s.State === 'RUNNING') { log(s.Name + ' => ' + s.DisplayName); }
//	}
//
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
//
//	for (const s of sessions) {
//	  log(s.Username + '@' + s.Client + ' active=' + s.Active + 's');
//	}
//
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

// EnumProcesses lists running processes via the Terminal Services Legacy API
// (Ctx_WinStation_API_service). This is the goimpacket-backed analogue of
// nmap smb-enum-processes (which reads winreg performance counters). Requires
// rights to open the WinStation server handle; TermService should be running.
//
// @example
// ```javascript
// const dcerpc = require('nuclei/dcerpc');
// const c = new dcerpc.Client('dc01.acme.local', 'acme.local', 'admin', 'P@ssw0rd');
// const procs = c.EnumProcesses();
//
//	for (const p of procs) {
//	  log(p.PID + ' ' + p.Name + ' session=' + p.SessionID);
//	}
//
// ```
func (c *Client) EnumProcesses() ([]ProcessEntry, error) {
	if !protocolstate.IsHostAllowed(c.nj.ExecutionId(), c.Host) {
		return nil, protocolstate.ErrHostDenied.Msgf(c.Host)
	}
	rpc, err := c.rpcOverNamedPipe(winstation.PipeCtxWinStation, winstation.LegacyAPIUUID, winstation.MajorVersion, winstation.MinorVersion)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rpc.Transport.Close()
	}()

	legacy := winstation.NewLegacyClient(rpc)
	handle, err := legacy.OpenServer()
	if err != nil {
		return nil, fmt.Errorf("winstation OpenServer: %w", err)
	}
	defer func() {
		_ = legacy.CloseServer(handle)
	}()

	raw, err := legacy.GetAllProcesses(handle)
	if err != nil {
		return nil, err
	}
	return mapProcessEntries(raw), nil
}

// EnumLoggedOnUsers lists users currently known to the workstation service
// via WKSSVC NetrWkstaUserEnum. Complements SamrEnumerateUsers (domain DB)
// and EnumSessions (SMB sessions).
//
// @example
// ```javascript
// const dcerpc = require('nuclei/dcerpc');
// const c = new dcerpc.Client('ws01.acme.local', 'acme.local', 'admin', 'P@ssw0rd');
// const users = c.EnumLoggedOnUsers();
// for (const u of users) { log(u.LogonDomain + '\\' + u.Username); }
// ```
func (c *Client) EnumLoggedOnUsers() ([]LoggedOnUser, error) {
	if !protocolstate.IsHostAllowed(c.nj.ExecutionId(), c.Host) {
		return nil, protocolstate.ErrHostDenied.Msgf(c.Host)
	}
	rpc, err := c.rpcOverNamedPipe("wkssvc", gpwkssvc.UUID, gpwkssvc.MajorVersion, gpwkssvc.MinorVersion)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rpc.Transport.Close()
	}()

	raw, err := gpwkssvc.NetrWkstaUserEnum(rpc)
	if err != nil {
		return nil, err
	}
	return mapLoggedOnUsers(raw), nil
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

func mapProcessEntries(raw []winstation.ProcessInfo) []ProcessEntry {
	out := make([]ProcessEntry, 0, len(raw))
	for _, e := range raw {
		out = append(out, ProcessEntry{
			Name:           e.ImageName,
			PID:            e.UniqueProcessId,
			SessionID:      e.SessionId,
			WorkingSetSize: e.WorkingSetSize,
			SID:            e.SID,
		})
	}
	return out
}

func mapLoggedOnUsers(raw []gpwkssvc.WkstaUserInfo1) []LoggedOnUser {
	out := make([]LoggedOnUser, 0, len(raw))
	for _, e := range raw {
		out = append(out, LoggedOnUser{
			Username:    e.Username,
			LogonDomain: e.LogonDomain,
			OthDomains:  e.OthDomains,
			LogonServer: e.LogonServer,
		})
	}
	return out
}
