package input

import (
	"testing"

	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/stretchr/testify/require"
)

func TestConvertInputToType(t *testing.T) {
	helper := &Helper{}

	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	require.NoError(t, err, "could not create hybrid map")
	helper.InputsHTTP = hm
	defer hm.Close()

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
		{"test.com", typeURL, "", ""},
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
		{"google.com", typeHostWithPort, "", ""},
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
