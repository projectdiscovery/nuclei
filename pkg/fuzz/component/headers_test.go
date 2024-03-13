package component

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestHeaderComponent(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", "test-agent")

	header := NewHeader()
	_, err = header.Parse(req)
	if err != nil {
		t.Fatal(err)
	}

	var keys []string
	var values []string
	_ = header.Iterate(func(key string, value interface{}) error {
		keys = append(keys, key)
		switch v := value.(type) {
		case string:
			values = append(values, v)
		case []string:
			values = append(values, v...)
		}
		return nil
	})

	require.Equal(t, []string{"User-Agent"}, keys, "unexpected keys")
	require.Equal(t, []string{"test-agent"}, values, "unexpected values")

	err = header.SetValue("User-Agent", "new-agent")
	if err != nil {
		t.Fatal(err)
	}

	rebuilt, err := header.Rebuild()
	if err != nil {
		t.Fatal(err)
	}

	require.Equal(t, "new-agent", rebuilt.Header.Get("User-Agent"), "unexpected header value")
}
