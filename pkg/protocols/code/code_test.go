//go:build linux || darwin

package code

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
)

func TestCodeProtocol(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-code"
	request := &Request{
		Engine: []string{"sh"},
		Source: "echo test",
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile code request")

	ctxArgs := contextargs.NewWithInput("")
	for event := range request.ExecuteWithResults(ctxArgs, nil, nil) {
		require.Nil(t, event.Error, "could not run code request")
		require.NotEmpty(t, event.Event.InternalEvent, "could not get event items")
	}
}
