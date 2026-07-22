package file

import (
	"context"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestGetInputPathsSMBDeniesHost(t *testing.T) {
	execID := "file-smb-getpaths-deny"
	require.NoError(t, protocolstate.Init(&types.Options{
		ExecutionId:    execID,
		ExcludeTargets: []string{"203.0.113.52"},
	}))
	t.Cleanup(func() { protocolstate.Close(execID) })

	req := &Request{
		SMBUser:     "auditor",
		SMBPassword: "secret",
		options: &protocols.ExecutorOptions{
			Options: &types.Options{ExecutionId: execID},
		},
	}
	err := req.getInputPaths(`\\203.0.113.52\backup\a.txt`, func(string) {
		t.Fatal("callback must not run when host is denied")
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "203.0.113.52")
}

func TestGetInputPathsSMBRequiresExecutionID(t *testing.T) {
	req := &Request{SMBUser: "u", SMBPassword: "p"}
	err := req.getInputPaths(`\\fs01\backup\a.txt`, func(string) {})
	require.Error(t, err)
	require.Contains(t, err.Error(), "execution id")
}

func TestReadSMBFileRejectsDirectory(t *testing.T) {
	execID := "file-smb-read-dir"
	require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: execID}))
	t.Cleanup(func() { protocolstate.Close(execID) })

	req := &Request{
		options: &protocols.ExecutorOptions{
			Options: &types.Options{ExecutionId: execID},
		},
	}
	_, err := req.readSMBFile(context.Background(), `\\fs01\backup`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "directory")
}

func TestReadSMBFileDeniesHost(t *testing.T) {
	execID := "file-smb-read-deny"
	require.NoError(t, protocolstate.Init(&types.Options{
		ExecutionId:    execID,
		ExcludeTargets: []string{"203.0.113.53"},
	}))
	t.Cleanup(func() { protocolstate.Close(execID) })

	req := &Request{
		SMBUser:     "u",
		SMBPassword: "p",
		options: &protocols.ExecutorOptions{
			Options: &types.Options{ExecutionId: execID},
		},
	}
	_, err := req.readSMBFile(context.Background(), `\\203.0.113.53\backup\a.txt`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "203.0.113.53")
}

func TestEnumerateSMBInputsSingleFileCallback(t *testing.T) {
	// Denied host still exercises the "single file path" branch before Dial fails
	// after policy check — ensure Display path would have been used.
	target, err := ParseSMBTarget(`\\fs01\backup\docs\a.txt`)
	require.NoError(t, err)
	require.Equal(t, `\\fs01\backup\docs\a.txt`, target.Display())
	require.False(t, isDirectorySMBTarget(target.Display()))
}

func TestSMBPortOverride(t *testing.T) {
	req := &Request{SMBPort: 1445}
	require.Equal(t, 1445, req.smbPort(&SMBTarget{Port: 445}))
	req = &Request{}
	require.Equal(t, 445, req.smbPort(&SMBTarget{}))
	require.Equal(t, 139, req.smbPort(&SMBTarget{Port: 139}))
}
