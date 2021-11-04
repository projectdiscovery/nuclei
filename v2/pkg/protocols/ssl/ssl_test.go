package ssl

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/stretchr/testify/require"
)

func TestSSLProtocol(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-ssl"
	request := &Request{}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile ssl request")

	err = request.ExecuteWithResults("google.com:443", nil, nil, func(event *output.InternalWrappedEvent) {})
	require.Nil(t, err, "could not run ssl request")
}

func TestGetAddress(t *testing.T) {
	address, _ := getAddress("https://google.com")
	require.Equal(t, "google.com:443", address, "could not get correct address")
}
