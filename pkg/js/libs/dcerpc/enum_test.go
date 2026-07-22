package dcerpc

import (
	"testing"

	gpsrvsvc "github.com/Mzack9999/goimpacket/pkg/dcerpc/srvsvc"
	gpsvcctl "github.com/Mzack9999/goimpacket/pkg/dcerpc/svcctl"
	gptsts "github.com/Mzack9999/goimpacket/pkg/dcerpc/tsts"
	gpwkssvc "github.com/Mzack9999/goimpacket/pkg/dcerpc/wkssvc"
	"github.com/stretchr/testify/require"
)

func TestMapServiceEntries(t *testing.T) {
	raw := []gpsvcctl.EnumServiceEntry{
		{
			ServiceName: "Spooler",
			DisplayName: "Print Spooler",
			Status:      gpsvcctl.ServiceStatus{CurrentState: gpsvcctl.SERVICE_RUNNING, ControlsAccepted: 1},
		},
		{
			ServiceName: "StoppedSvc",
			DisplayName: "Stopped",
			Status:      gpsvcctl.ServiceStatus{CurrentState: gpsvcctl.SERVICE_STOPPED},
		},
	}
	got := mapServiceEntries(raw)
	require.Len(t, got, 2)
	require.Equal(t, "Spooler", got[0].Name)
	require.Equal(t, "Print Spooler", got[0].DisplayName)
	require.Equal(t, "RUNNING", got[0].State)
	require.Equal(t, uint32(gpsvcctl.SERVICE_RUNNING), got[0].StateCode)
	require.Equal(t, "STOPPED", got[1].State)
}

func TestMapSessionEntries(t *testing.T) {
	raw := []gpsrvsvc.SessionInfo10{
		{Cname: `\\client1`, Username: "alice", ActiveTime: 10, IdleTime: 2},
		{Cname: `\\client2`, Username: "bob", ActiveTime: 0, IdleTime: 99},
	}
	got := mapSessionEntries(raw)
	require.Len(t, got, 2)
	require.Equal(t, `\\client1`, got[0].Client)
	require.Equal(t, "alice", got[0].Username)
	require.Equal(t, uint32(10), got[0].Active)
	require.Equal(t, uint32(2), got[0].Idle)
	require.Equal(t, "bob", got[1].Username)
}

func TestMapProcessEntries(t *testing.T) {
	raw := []gptsts.ProcessInfo{
		{ImageName: "lsass.exe", UniqueProcessId: 628, SessionId: 0, WorkingSetSize: 1024, SID: "S-1-5-18"},
		{ImageName: "explorer.exe", UniqueProcessId: 1200, SessionId: 1},
	}
	got := mapProcessEntries(raw)
	require.Len(t, got, 2)
	require.Equal(t, "lsass.exe", got[0].Name)
	require.Equal(t, uint32(628), got[0].PID)
	require.Equal(t, "S-1-5-18", got[0].SID)
	require.Equal(t, uint32(1), got[1].SessionID)
}

func TestMapLoggedOnUsers(t *testing.T) {
	raw := []gpwkssvc.WkstaUserInfo1{
		{Username: "alice", LogonDomain: "CORP", LogonServer: "DC01"},
	}
	got := mapLoggedOnUsers(raw)
	require.Len(t, got, 1)
	require.Equal(t, "alice", got[0].Username)
	require.Equal(t, "CORP", got[0].LogonDomain)
	require.Equal(t, "DC01", got[0].LogonServer)
}

func TestMapServiceEntriesEmpty(t *testing.T) {
	require.Empty(t, mapServiceEntries(nil))
	require.Empty(t, mapSessionEntries(nil))
	require.Empty(t, mapProcessEntries(nil))
	require.Empty(t, mapLoggedOnUsers(nil))
}
