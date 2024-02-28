package component

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestQueryComponent(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com?foo=bar", nil)
	if err != nil {
		t.Fatal(err)
	}

	query := NewQuery()
	_, err = query.Parse(req)
	if err != nil {
		t.Fatal(err)
	}

	var keys []string
	var values []string
	_ = query.Iterate(func(key string, value interface{}) error {
		keys = append(keys, key)
		values = append(values, value.(string))
		return nil
	})

	require.Equal(t, []string{"foo"}, keys, "unexpected keys")
	require.Equal(t, []string{"bar"}, values, "unexpected values")

	err = query.SetValue("foo", "baz")
	if err != nil {
		t.Fatal(err)
	}

	rebuilt, err := query.Rebuild()
	if err != nil {
		t.Fatal(err)
	}

	require.Equal(t, "foo=baz", rebuilt.URL.RawQuery, "unexpected query string")
	require.Equal(t, "https://example.com?foo=baz", rebuilt.URL.String(), "unexpected url")
}
