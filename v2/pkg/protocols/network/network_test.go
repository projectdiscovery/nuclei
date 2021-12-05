package network

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

func TestNetworkCompileMake(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-network"
	request := &Request{
		ID:       templateID,
		Address:  []string{"tls://{{Host}}:443"},
		ReadSize: 1024,
		Inputs:   []*Input{{Data: "test-data"}},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile network request")

	require.Equal(t, 1, len(request.addresses), "could not get correct number of input address")
	t.Run("check-tls-with-port", func(t *testing.T) {
		require.True(t, request.addresses[0].tls, "could not get correct port for host")
	})
}
