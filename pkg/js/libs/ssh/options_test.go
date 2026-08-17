package ssh

import (
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestOptionsToConnectMapsFields(t *testing.T) {
	opts := SSHOptions{
		Host:          "ssh.example.com",
		Port:          2222,
		User:          "alice",
		Password:      "secret",
		PrivateKey:    "-----BEGIN PRIVATE KEY-----\n...",
		Timeout:       15,
		ClientVersion: "SSH-2.0-OpenSSH_8.9",
	}

	got := optionsToConnect(opts, "exec-1")
	require.Equal(t, "ssh.example.com", got.Host)
	require.Equal(t, 2222, got.Port)
	require.Equal(t, "alice", got.User)
	require.Equal(t, "secret", got.Password)
	require.Equal(t, "-----BEGIN PRIVATE KEY-----\n...", got.PrivateKey)
	require.Equal(t, 15*time.Second, got.Timeout)
	require.Equal(t, "SSH-2.0-OpenSSH_8.9", got.ClientVersion)
	require.Equal(t, "exec-1", got.ExecutionId)
}

func TestOptionsToConnectLeavesDefaultTimeoutWhenUnset(t *testing.T) {
	got := optionsToConnect(SSHOptions{Host: "h", Port: 22}, "exec")
	require.Equal(t, time.Duration(0), got.Timeout)
}

func TestConnectOptionsValidate(t *testing.T) {
	t.Run("missing host", func(t *testing.T) {
		err := (&connectOptions{Port: 22, ExecutionId: "x"}).validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "host is required")
	})
	t.Run("missing port", func(t *testing.T) {
		err := (&connectOptions{Host: "h", ExecutionId: "x"}).validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "port is required")
	})
	t.Run("default timeout", func(t *testing.T) {
		executionID := t.Name()
		require.NoError(t, protocolstate.Init(&types.Options{ExecutionId: executionID}))
		t.Cleanup(func() { protocolstate.Close(executionID) })

		opts := &connectOptions{Host: "example.com", Port: 22, Timeout: 0, ExecutionId: executionID}
		require.NoError(t, opts.validate())
		require.Equal(t, 10*time.Second, opts.Timeout)
	})
}

func TestSSHOptionsPasswordAndKeyCanBothBeSet(t *testing.T) {
	opts := SSHOptions{
		Host:       "h",
		Port:       22,
		User:       "u",
		Password:   "p",
		PrivateKey: "k",
	}
	got := optionsToConnect(opts, "e")
	require.Equal(t, "p", got.Password)
	require.Equal(t, "k", got.PrivateKey)
}

func TestConnectOptionsDeniesRestrictedLocalHostBeforeDial(t *testing.T) {
	executionID := t.Name()
	require.NoError(t, protocolstate.Init(&types.Options{
		ExecutionId:                executionID,
		RestrictLocalNetworkAccess: true,
	}))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	err := optionsToConnect(SSHOptions{Host: "127.0.0.1", Port: 22}, executionID).validate()
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "network policy") && strings.Contains(err.Error(), "127.0.0.1"))
}
