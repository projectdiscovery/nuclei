package eventcreator

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/stretchr/testify/require"
)

func TestSetRecordRestoresTheCallbackItReplaced(t *testing.T) {
	var calls []string
	first := RecordFunc(func(protocols.Request, output.InternalEvent) { calls = append(calls, "first") })
	second := RecordFunc(func(protocols.Request, output.InternalEvent) { calls = append(calls, "second") })

	require.Nil(t, SetRecord(first))
	previous := SetRecord(second)
	(*record.Load())(nil, nil)
	// a second runner stopping puts the first one's recorder back, not nil
	SetRecord(previous)
	(*record.Load())(nil, nil)
	require.Equal(t, []string{"second", "first"}, calls)

	SetRecord(nil)
	require.Nil(t, record.Load())
}
