package utils

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
)

func TestHasOfflineHTTPResponse(t *testing.T) {
	meta := contextargs.NewMetaInput()
	require.False(t, HasOfflineHTTPResponse(meta, templateTypes.OfflineHTTPProtocol))

	meta.ReqResp = &types.RequestResponse{}
	require.False(t, HasOfflineHTTPResponse(meta, templateTypes.OfflineHTTPProtocol))

	meta.ReqResp.Response = &types.HttpResponse{Raw: "HTTP/1.1 200 OK\r\n\r\n"}
	require.True(t, HasOfflineHTTPResponse(meta, templateTypes.OfflineHTTPProtocol))
	require.False(t, HasOfflineHTTPResponse(meta, templateTypes.HTTPProtocol))
	require.False(t, HasOfflineHTTPResponse(nil, templateTypes.OfflineHTTPProtocol))
}
