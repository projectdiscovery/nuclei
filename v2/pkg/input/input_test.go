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
	helper.inputsHTTP = hm
	defer hm.Close()

	_ = hm.Set("google.com", []byte("https://google.com"))

	tests := []struct {
		input     string
		inputType inputType
		result    string
	}{
		// host
		{"google.com", inputTypeHost, "google.com"},
		{"google.com:443", inputTypeHost, "google.com"},
		{"https://google.com", inputTypeHost, "google.com"},
		{"https://google.com:443", inputTypeHost, "google.com"},

		// url
		{"test.com", inputTypeURL, ""},
		{"google.com", inputTypeURL, "https://google.com"},
		{"https://google.com", inputTypeURL, "https://google.com"},

		// file
		{"google.com:443", inputTypeFilepath, ""},
		{"https://google.com:443", inputTypeFilepath, ""},
		{"/example/path", inputTypeFilepath, "/example/path"},
		{"input_test.go", inputTypeFilepath, "input_test.go"},
		{"../input", inputTypeFilepath, "../input"},
		{"input_test.*", inputTypeFilepath, "input_test.*"},

		// host-port
		{"google.com", inputTypeHostPort, ""},
		{"google.com:443", inputTypeHostPort, "google.com:443"},
		{"https://google.com", inputTypeHostPort, "google.com:443"},
		{"https://google.com:443", inputTypeHostPort, "google.com:443"},

		// websocket
		{"google.com", inputTypeWebsocket, ""},
		{"google.com:443", inputTypeWebsocket, ""},
		{"https://google.com:443", inputTypeWebsocket, ""},
		{"wss://google.com", inputTypeWebsocket, "wss://google.com"},
	}

	for _, test := range tests {
		result := helper.convertInputToType(test.input, test.inputType)
		require.Equal(t, test.result, result, "could not get correct result %+v", test)
	}
}
