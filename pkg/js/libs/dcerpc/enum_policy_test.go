package dcerpc

import (
	"testing"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

const enumDeniedHost = "203.0.113.51"

func newDeniedEnumClient(t *testing.T, executionID string) *Client {
	t.Helper()
	require.NoError(t, protocolstate.Init(&types.Options{
		ExecutionId:    executionID,
		ExcludeTargets: []string{enumDeniedHost},
	}))
	t.Cleanup(func() { protocolstate.Close(executionID) })

	runtime := goja.New()
	runtime.SetContextValue("executionId", executionID)
	return &Client{
		Host: enumDeniedHost,
		nj:   utils.NewNucleiJS(runtime),
	}
}

func TestEnumServicesDeniesHostBeforeDial(t *testing.T) {
	c := newDeniedEnumClient(t, "dcerpc-enum-services-deny")
	_, err := c.EnumServices()
	require.Error(t, err)
	require.Contains(t, err.Error(), enumDeniedHost)
}

func TestEnumSessionsDeniesHostBeforeDial(t *testing.T) {
	c := newDeniedEnumClient(t, "dcerpc-enum-sessions-deny")
	_, err := c.EnumSessions()
	require.Error(t, err)
	require.Contains(t, err.Error(), enumDeniedHost)
}

func TestEnumProcessesDeniesHostBeforeDial(t *testing.T) {
	c := newDeniedEnumClient(t, "dcerpc-enum-processes-deny")
	_, err := c.EnumProcesses()
	require.Error(t, err)
	require.Contains(t, err.Error(), enumDeniedHost)
}

func TestEnumLoggedOnUsersDeniesHostBeforeDial(t *testing.T) {
	c := newDeniedEnumClient(t, "dcerpc-enum-loggedon-deny")
	_, err := c.EnumLoggedOnUsers()
	require.Error(t, err)
	require.Contains(t, err.Error(), enumDeniedHost)
}
