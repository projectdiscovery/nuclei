package component

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestURLComponent(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com/testpath", nil)
	if err != nil {
		t.Fatal(err)
	}

	urlComponent := NewURL()
	err = urlComponent.Parse(req)
	if err != nil {
		t.Fatal(err)
	}

	var keys []string
	var values []string
	urlComponent.Iterate(func(key string, value interface{}) {
		keys = append(keys, key)
		values = append(values, value.(string))
	})

	require.Equal(t, []string{"value"}, keys, "unexpected keys")
	require.Equal(t, []string{"/testpath"}, values, "unexpected values")

	// Update the URL path
	err = urlComponent.SetValue("value", "/newpath")
	if err != nil {
		t.Fatal(err)
	}

	// Rebuild the request with the updated URL
	rebuilt, err := urlComponent.Rebuild()
	if err != nil {
		t.Fatal(err)
	}

	// Assert that the rebuilt request's URL is as expected
	require.Equal(t, "/newpath", rebuilt.URL.Path, "unexpected URL path")
	require.Equal(t, "https://example.com/newpath", rebuilt.URL.String(), "unexpected full URL")
}
