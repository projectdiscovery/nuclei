//go:build linux || darwin

package code

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
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
	templateInfo := &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	}
	executerOpts, err := testutils.NewMockExecuterOptions(options, templateInfo)
	require.Nil(t, err, "could not create executer options")

	err = request.Compile(executerOpts)
	require.Nil(t, err, "could not compile code request")

	var gotEvent output.InternalEvent
	ctxArgs := contextargs.NewWithInput(context.Background(), "")
	err = request.ExecuteWithResults(ctxArgs, nil, nil, func(event *output.InternalWrappedEvent) {
		gotEvent = event.InternalEvent
	})
	require.Nil(t, err, "could not run code request")
	require.NotEmpty(t, gotEvent, "could not get event items")
}
