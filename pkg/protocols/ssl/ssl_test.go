package ssl

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
)

func TestSSLProtocol(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-ssl"
	request := &Request{
		ID:      "duration-ssl",
		Address: "{{Hostname}}",
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	executerOpts.IsMultiProtocol = true
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile ssl request")
	require.Equal(t, "duration-ssl", request.GetID())

	var gotEvent output.InternalEvent
	ctxArgs := contextargs.NewWithInput(context.Background(), "scanme.sh:443")
	err = request.ExecuteWithResults(ctxArgs, nil, nil, func(event *output.InternalWrappedEvent) {
		gotEvent = event.InternalEvent
	})
	require.Nil(t, err, "could not run ssl request")
	require.NotEmpty(t, gotEvent, "could not get event items")
	requireDurationField(t, gotEvent, "duration")
	extractor := &extractors.Extractor{
		Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.DSLExtractor},
		DSL:  []string{"duration"},
	}
	require.NoError(t, extractor.CompileExtractors())
	require.NotEmpty(t, request.Extract(gotEvent, extractor))

	values := executerOpts.GetTemplateCtx(ctxArgs.MetaInput).GetAll()
	require.Equal(t, gotEvent["duration"], values["duration-ssl_duration"])
}

func requireDurationField(t *testing.T, event output.InternalEvent, key string) {
	t.Helper()

	value, ok := event[key].(float64)
	require.Truef(t, ok, "expected %s to be a float64 duration", key)
	require.Greater(t, value, float64(0))
	require.Less(t, value, float64(60))
}
