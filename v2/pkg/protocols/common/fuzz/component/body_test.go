package component

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestBodyComponent(t *testing.T) {
	req, err := retryablehttp.NewRequest("POST", "https://example.com", strings.NewReader(`{"foo":"bar"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	body := New(RequestBodyComponent)
	_, err = body.Parse(req)
	if err != nil {
		t.Fatal(err)
	}

	var keys []string
	var values []string
	body.Iterate(func(key string, value interface{}) {
		keys = append(keys, key)
		values = append(values, value.(string))
	})

	require.Equal(t, []string{"foo"}, keys, "unexpected keys")
	require.Equal(t, []string{"bar"}, values, "unexpected values")

	body.SetValue("foo", "baz")

	rebuilt, err := body.Rebuild()
	if err != nil {
		t.Fatal(err)
	}

	newBody, err := io.ReadAll(rebuilt.Body)
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, `{"foo":"baz"}`, string(newBody), "unexpected body")
}

func TestBodyXMLComponent(t *testing.T) {
	var body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>"

	req, err := retryablehttp.NewRequest("POST", "https://example.com", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/xml")

	bodyComponent := New(RequestBodyComponent)
	parsed, err := bodyComponent.Parse(req)
	if err != nil {
		t.Fatal(err)
	}
	require.True(t, parsed, "could not parse body")

	bodyComponent.Iterate(func(key string, value interface{}) {
		fmt.Printf("key: %v value: %v\n", key, value)
	})

	bodyComponent.SetValue("stockCheck~productId", "2'6842")
	rebuilt, err := bodyComponent.Rebuild()
	if err != nil {
		t.Fatal(err)
	}

	newBody, err := io.ReadAll(rebuilt.Body)
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><stockCheck><productId>2'6842</productId><storeId>1</storeId></stockCheck>", string(newBody), "unexpected body")
}
