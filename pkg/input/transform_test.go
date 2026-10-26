package input

import (
	"testing"

	"github.com/projectdiscovery/hmap/store/hybrid"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/stretchr/testify/require"
)

func TestTransformPinned(t *testing.T) {
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	require.NoError(t, err, "could not create hybrid map")
	defer func() {
		_ = hm.Close()
	}()
	helper := &Helper{InputsHTTP: hm}

	_ = hm.Set(ProbeKey("app.test", ""), []byte("http://app.test"))
	_ = hm.Set(ProbeKey("app.test", "127.0.0.2"), []byte("https://app.test"))

	require.Equal(t, "https://app.test", helper.TransformPinned("app.test", "127.0.0.2", templateTypes.HTTPProtocol), "the probe made through the pinned ip")
	require.Equal(t, "http://app.test", helper.TransformPinned("app.test", "", templateTypes.HTTPProtocol), "an unpinned input")
	require.Equal(t, "app.test", helper.TransformPinned("app.test", "127.0.0.3", templateTypes.HTTPProtocol), "an ip without a probe of its own does not take the unpinned result")
	require.Equal(t, "app.test", helper.TransformPinned("app.test", "127.0.0.2", templateTypes.DNSProtocol), "a protocol that is not probed")
	require.NotEqual(t, ProbeKey("u.example@192.0.2.10", ""), ProbeKey("u.example", "192.0.2.10"), "an input holding an @ does not collide with a pinned one")
}

func TestConvertInputToType(t *testing.T) {
	helper := &Helper{}

	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	require.NoError(t, err, "could not create hybrid map")
	helper.InputsHTTP = hm
	defer func() {
		_ = hm.Close()
	}()

	_ = hm.Set("google.com", []byte("https://google.com"))

	tests := []struct {
		input       string
		inputType   inputType
		result      string
		defaultPort string
	}{
		// host
		{"google.com", typeHostOnly, "google.com", ""},
		{"google.com:443", typeHostOnly, "google.com", ""},
		{"https://google.com", typeHostOnly, "google.com", ""},
		{"https://google.com:443", typeHostOnly, "google.com", ""},

		// url
		{"test.com", typeURL, "test.com", ""},
		{"google.com", typeURL, "https://google.com", ""},
		{"https://google.com", typeURL, "https://google.com", ""},

		// file
		{"google.com:443", typeFilepath, "", ""},
		{"https://google.com:443", typeFilepath, "", ""},
		{"/example/path", typeFilepath, "/example/path", ""},
		{"input_test.go", typeFilepath, "input_test.go", ""},
		{"../input", typeFilepath, "../input", ""},
		{"input_test.*", typeFilepath, "input_test.*", ""},

		// host-port
		{"google.com", typeHostWithPort, "google.com", ""},
		{"google.com:443", typeHostWithPort, "google.com:443", ""},
		{"https://google.com", typeHostWithPort, "google.com:443", ""},
		{"https://google.com:443", typeHostWithPort, "google.com:443", ""},
		// host-port with default port
		{"google.com", typeHostWithPort, "google.com:443", "443"},

		// host with optional port
		{"google.com", typeHostWithOptionalPort, "google.com", ""},
		{"google.com:443", typeHostWithOptionalPort, "google.com:443", ""},
		{"https://google.com", typeHostWithOptionalPort, "google.com:443", ""},
		{"https://google.com:443", typeHostWithOptionalPort, "google.com:443", ""},
		// host with optional port and default port
		{"google.com", typeHostWithOptionalPort, "google.com:443", "443"},

		// websocket
		{"google.com", typeWebsocket, "", ""},
		{"google.com:443", typeWebsocket, "", ""},
		{"https://google.com:443", typeWebsocket, "", ""},
		{"wss://google.com", typeWebsocket, "wss://google.com", ""},
	}

	for _, test := range tests {
		result := helper.convertInputToType(test.input, test.inputType, test.defaultPort)
		require.Equal(t, test.result, result, "could not get correct result %+v", test)
	}
}
