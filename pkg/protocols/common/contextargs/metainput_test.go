package contextargs

import (
	"testing"

	inputtypes "github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/stretchr/testify/require"
)

func TestMetaInputMarshalAndUnmarshalString(t *testing.T) {
	input := NewMetaInput()
	input.Input = "https://example.com"
	input.CustomIP = "192.0.2.10"

	encoded, err := input.MarshalString()
	require.NoError(t, err)
	require.Equal(t, "{\"input\":\"https://example.com\",\"customIP\":\"192.0.2.10\"}\n", encoded)

	decoded := NewMetaInput()
	require.NoError(t, decoded.Unmarshal(encoded))
	require.Equal(t, input.Input, decoded.Input)
	require.Equal(t, input.CustomIP, decoded.CustomIP)
}

func TestMetaInputLegacyIdentityRemainsStableWithoutTargetFilter(t *testing.T) {
	plain := NewMetaInput()
	plain.Input = "https://plain.example"
	require.Equal(t, plain.Input, plain.ID())
	require.Equal(
		t,
		getMd5Hash("template-id:https://plain.example:"),
		plain.GetScanHash("template-id"),
	)

	input := NewMetaInput()
	input.Input = "https://example.com"
	input.CustomIP = "192.0.2.10"

	require.Equal(t, "https://example.com-192.0.2.10", input.ID())
	require.Equal(
		t,
		getMd5Hash("template-id:https://example.com:192.0.2.10"),
		input.GetScanHash("template-id"),
	)

	requestURL, err := urlutil.ParseAbsoluteURL("https://raw.example/request", false)
	require.NoError(t, err)
	raw := &inputtypes.RequestResponse{URL: *requestURL}
	requestInput := NewMetaInput()
	requestInput.Input = requestURL.String()
	requestInput.ReqResp = raw
	require.Equal(t, raw.ID(), requestInput.ID())
	require.Equal(
		t,
		getMd5Hash("template-id:"+requestInput.Input+":"+raw.ID()),
		requestInput.GetScanHash("template-id"),
	)
}

func TestMetaInputTargetFilterChangesIdentity(t *testing.T) {
	first := NewMetaInput()
	first.Input = "https://example.com"
	first.TargetFilter = &TargetFilter{HasTags: true, Tags: []string{"apache"}}
	first.TargetFilter.Prepare(first.TargetFilter.Tags, nil, nil, nil, nil, false)

	second := NewMetaInput()
	second.Input = first.Input
	second.TargetFilter = &TargetFilter{HasTags: true, Tags: []string{"nginx"}}
	second.TargetFilter.Prepare(second.TargetFilter.Tags, nil, nil, nil, nil, false)

	require.NotEqual(t, first.ID(), second.ID())
	require.NotEqual(t, first.GetScanHash("template-id"), second.GetScanHash("template-id"))
}
