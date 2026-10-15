package smb

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestListSharesWithOptionsRejectsInvalidHostPort(t *testing.T) {
	_, err := listSharesWithOptions(t.Context(), "exec", SMBOptions{Host: "", Port: 445})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid host or port")

	_, err = listSharesWithOptions(t.Context(), "exec", SMBOptions{Host: "acme.com", Port: 0})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid host or port")
}

func TestListSharesWithOptionsDeniesRestrictedLocalHostBeforeDial(t *testing.T) {
	executionID := t.Name()
	require.NoError(t, protocolstate.Init(&types.Options{
		ExecutionId:                executionID,
		RestrictLocalNetworkAccess: true,
	}))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	_, err := listSharesWithOptions(context.Background(), executionID, SMBOptions{
		Host: "127.0.0.1", Port: 445, Domain: "ACME", Timeout: 1,
	})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "network policy") && strings.Contains(err.Error(), "127.0.0.1"))
}

func TestSMBOptionsFields(t *testing.T) {
	opts := SMBOptions{
		Host:     "dc.acme.com",
		Port:     445,
		User:     "Administrator",
		Password: "secret",
		Hash:     "31d6cfe0d16ae931b73c59d7e0c089c0",
		Domain:   "ACME",
		Timeout:  15,
	}
	require.Equal(t, "ACME", opts.Domain)
	require.Equal(t, 15, opts.Timeout)
	require.Equal(t, "31d6cfe0d16ae931b73c59d7e0c089c0", opts.Hash)
}

func TestSMBDialContextUsesShorterConfiguredTimeout(t *testing.T) {
	parent, cancelParent := context.WithTimeout(t.Context(), time.Minute)
	defer cancelParent()

	dialCtx, cancelDial := smbDialContext(parent, 20*time.Millisecond)
	defer cancelDial()

	parentDeadline, ok := parent.Deadline()
	require.True(t, ok)
	dialDeadline, ok := dialCtx.Deadline()
	require.True(t, ok)
	require.True(t, dialDeadline.Before(parentDeadline))
	require.WithinDuration(t, time.Now().Add(20*time.Millisecond), dialDeadline, 10*time.Millisecond)
}
