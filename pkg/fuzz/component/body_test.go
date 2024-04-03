package component

import (
	"bytes"
	"io"
	"mime/multipart"
	"strings"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	urlutil "github.com/projectdiscovery/utils/url"
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
	_ = body.Iterate(func(key string, value interface{}) error {
		keys = append(keys, key)
		values = append(values, value.(string))
		return nil
	})

	require.Equal(t, []string{"foo"}, keys, "unexpected keys")
	require.Equal(t, []string{"bar"}, values, "unexpected values")

	_ = body.SetValue("foo", "baz")

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

	_ = bodyComponent.SetValue("stockCheck~productId", "2'6842")
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

func TestBodyFormComponent(t *testing.T) {
	formData := urlutil.NewOrderedParams()
	formData.Set("key1", "value1")
	formData.Set("key2", "value2")

	req, err := retryablehttp.NewRequest("POST", "https://example.com", strings.NewReader(formData.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	body := New(RequestBodyComponent)
	_, err = body.Parse(req)
	if err != nil {
		t.Fatal(err)
	}

	var keys []string
	var values []string
	_ = body.Iterate(func(key string, value interface{}) error {
		keys = append(keys, key)
		values = append(values, value.(string))
		return nil
	})

	require.ElementsMatch(t, []string{"key1", "key2"}, keys, "unexpected keys")
	require.ElementsMatch(t, []string{"value1", "value2"}, values, "unexpected values")

	_ = body.SetValue("key1", "updatedValue1")

	rebuilt, err := body.Rebuild()
	if err != nil {
		t.Fatal(err)
	}

	newBody, err := io.ReadAll(rebuilt.Body)
	if err != nil {
		t.Fatal(err)
	}
	require.Equal(t, "key1=updatedValue1&key2=value2", string(newBody), "unexpected body")
}

func TestMultiPartFormComponent(t *testing.T) {
	formData := &bytes.Buffer{}
	writer := multipart.NewWriter(formData)

	// Hypothetical form fields
	_ = writer.WriteField("username", "testuser")
	_ = writer.WriteField("password", "testpass")

	contentType := writer.FormDataContentType()
	_ = writer.Close()

	req, err := retryablehttp.NewRequest("POST", "https://example.com", formData)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)

	body := New(RequestBodyComponent)
	_, err = body.Parse(req)
	if err != nil {
		t.Fatal(err)
	}

	var keys []string
	var values []string
	_ = body.Iterate(func(key string, value interface{}) error {
		keys = append(keys, key)
		values = append(values, value.(string))
		return nil
	})

	require.ElementsMatch(t, []string{"username", "password"}, keys, "unexpected keys")
	require.ElementsMatch(t, []string{"testuser", "testpass"}, values, "unexpected values")

	// Update a value in the form
	_ = body.SetValue("password", "updatedTestPass")

	rebuilt, err := body.Rebuild()
	if err != nil {
		t.Fatal(err)
	}

	newBody, err := io.ReadAll(rebuilt.Body)
	if err != nil {
		t.Fatal(err)
	}

	// Check if the body contains the updated multipart form data
	require.Contains(t, string(newBody), "updatedTestPass", "unexpected body content")
	require.Contains(t, string(newBody), "username", "unexpected body content")
	require.Contains(t, string(newBody), "testuser", "unexpected body content")
}
