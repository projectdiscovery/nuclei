package network

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/portutil"
)

func TestResolvePort(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{input: "80", expected: "80"},
		{input: "443", expected: "443"},
		{input: "ftp", expected: "21"},
		{input: "ssh", expected: "22"},
		{input: "smtp", expected: "25"},
		{input: "http", expected: "80"},
		{input: "https", expected: "443"},
		{input: "mysql", expected: "3306"},
		{input: "0", wantErr: true},
		{input: "65536", wantErr: true},
		{input: "nonsense", wantErr: true},
		{input: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := portutil.ResolvePort(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestCompileWithServiceName(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-network-service"
	request := &Request{
		ID:       templateID,
		Address:  []string{"{{Host}}"},
		Port:     "ftp,ssh",
		ReadSize: 1024,
		Inputs:   []*Input{{Data: "test-data"}},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.NoError(t, err)
	require.Equal(t, []string{"21", "22"}, request.ports)
}

func TestCompileDeduplicatesPorts(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-network-dedup"
	request := &Request{
		ID:       templateID,
		Address:  []string{"{{Host}}"},
		Port:     "ftp, 21, ssh, 22",
		ReadSize: 1024,
		Inputs:   []*Input{{Data: "test-data"}},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.NoError(t, err)
	require.Equal(t, []string{"21", "22"}, request.ports)
}

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
