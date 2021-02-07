package fuzzing

import (
	"bytes"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestNormalizeNetHTTPRequest(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com/test?a=b", nil)
	require.Nil(t, err, "could not create http request")

	newReq, err := retryablehttp.FromRequest(req)
	require.Nil(t, err, "could not create http request")

	normalized, err := NormalizeRequest(newReq)
	require.Nil(t, err, "could not create normalized request")
	require.Equal(t, &NormalizedRequest{
		Host:        "example.com",
		Scheme:      "http",
		Path:        "/test",
		Method:      "GET",
		QueryValues: map[string][]string{"a": []string{"b"}},
		Headers:     map[string][]string{},
	}, normalized, "could not get correct normalized GET request")

	req, err = http.NewRequest("POST", "http://example.com/?a=b", nil)
	require.Nil(t, err, "could not create http request")
	req.Header.Set("Authorization", "test-value")
	req.Header.Set("Cookie", "name=value")

	newReq, err = retryablehttp.FromRequest(req)
	require.Nil(t, err, "could not create http request")

	normalized, err = NormalizeRequest(newReq)
	require.Nil(t, err, "could not create normalized post request")
	require.Equal(t, &NormalizedRequest{
		Host:        "example.com",
		Scheme:      "http",
		Path:        "/",
		Method:      "POST",
		Body:        "",
		QueryValues: map[string][]string{"a": []string{"b"}},
		Headers:     map[string][]string{"Authorization": []string{"test-value"}},
		Cookies:     map[string][]string{"name": []string{"value"}},
	}, normalized, "could not get correct normalized POST request")
}

func TestNormalizeNetHTTPMultipartRequest(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.com", nil)
	require.Nil(t, err, "could not create http request")

	buffer := new(bytes.Buffer)
	writer := multipart.NewWriter(buffer)
	part, err := writer.CreateFormFile("file", "file.txt")
	if err != nil {
		require.Nil(t, err, "could not create form")
	}
	_, err = io.Copy(part, strings.NewReader("hello world"))

	params := map[string]string{"test": "value", "form": "data"}
	for key, val := range params {
		_ = writer.WriteField(key, val)
	}
	writer.Close()
	req.Body = ioutil.NopCloser(buffer)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	newReq, err := retryablehttp.FromRequest(req)
	require.Nil(t, err, "could not create http request")

	normalized, err := NormalizeRequest(newReq)
	require.Nil(t, err, "could not create normalized request")

	require.Equal(t, &NormalizedRequest{
		Host:   "example.com",
		Scheme: "http",
		Path:   "",
		Method: "POST",
		MultipartBody: map[string]NormalizedMultipartField{
			"test": {Value: "value"},
			"form": {Value: "data"},
			"file": {Value: "hello world", Filename: "file.txt"},
		},
		QueryValues: map[string][]string{},
		Headers:     map[string][]string{},
	}, normalized, "could not get correct normalized GET request")
}

func TestNormalizeNetHTTPFormRequest(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.com", nil)
	require.Nil(t, err, "could not create http request")

	form := make(url.Values)
	form.Set("name", "hacker")
	form.Set("password", "pass")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Body = ioutil.NopCloser(strings.NewReader(form.Encode()))

	newReq, err := retryablehttp.FromRequest(req)
	require.Nil(t, err, "could not create http request")

	normalized, err := NormalizeRequest(newReq)
	require.Nil(t, err, "could not create normalized request")

	require.Equal(t, &NormalizedRequest{
		Host:        "example.com",
		Scheme:      "http",
		Path:        "",
		Method:      "POST",
		FormData:    map[string][]string{"name": []string{"hacker"}, "password": []string{"pass"}},
		QueryValues: map[string][]string{},
		Headers:     map[string][]string{"Content-Type": []string{"application/x-www-form-urlencoded"}},
	}, normalized, "could not get correct normalized GET request")
}

func TestNormalizeNetHTTPJSONRequest(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.com", strings.NewReader(`
	{
		"name": {"first": "Tom", "last": "Anderson"},
		"children": ["Sara","Alex","Jack"]
	}`))
	require.Nil(t, err, "could not create http request")
	req.Header.Set("Content-Type", "application/json")

	newReq, err := retryablehttp.FromRequest(req)
	require.Nil(t, err, "could not create http request")

	normalized, err := NormalizeRequest(newReq)
	require.Nil(t, err, "could not create normalized request")

	require.Equal(t, &NormalizedRequest{
		Host:   "example.com",
		Scheme: "http",
		Path:   "",
		Method: "POST",
		JSONData: map[string]interface{}{
			"name":     map[string]interface{}{"first": "Tom", "last": "Anderson"},
			"children": []interface{}{"Sara", "Alex", "Jack"},
		},
		QueryValues: map[string][]string{},
		Headers:     map[string][]string{"Content-Type": []string{"application/json"}},
	}, normalized, "could not get correct normalized GET request")
}

func TestNormalizeNetHTTPXMLRequest(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.com", strings.NewReader(`<note>
  <to>Tove</to>
  <from>Jani</from>
</note>`))
	require.Nil(t, err, "could not create http request")
	req.Header.Set("Content-Type", "text/xml")

	newReq, err := retryablehttp.FromRequest(req)
	require.Nil(t, err, "could not create http request")

	normalized, err := NormalizeRequest(newReq)
	require.Nil(t, err, "could not create normalized request")

	require.Equal(t, &NormalizedRequest{
		Host:   "example.com",
		Scheme: "http",
		Path:   "",
		Method: "POST",
		XMLData: map[string]interface{}{
			"note": map[string]interface{}{"to": "Tove", "from": "Jani"},
		},
		QueryValues: map[string][]string{},
		Headers:     map[string][]string{"Content-Type": []string{"text/xml"}},
	}, normalized, "could not get correct normalized GET request")
}
