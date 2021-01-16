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

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestNormalizeNetHTTPRequest(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com/test?a=b", nil)
	require.Nil(t, err, "could not create http request")

	normalized, err := NormalizeRequest(req)
	require.Nil(t, err, "could not create normalized request")
	require.Equal(t, &NormalizedRequest{
		Host:        "example.com",
		Scheme:      "http",
		Path:        "/test",
		Method:      "GET",
		QueryValues: map[string][]string{"a": []string{"b"}},
		Headers:     map[string][]string{},
	}, normalized, "could not get correct normalized GET request")

	req, err = http.NewRequest("POST", "http://example.com/?a=b", strings.NewReader("{'a':'test-body'}"))
	require.Nil(t, err, "could not create http request")
	req.Header.Set("Authorization", "test-value")
	req.Header.Set("Cookie", "name=value")

	normalized, err = NormalizeRequest(req)
	require.Nil(t, err, "could not create normalized post request")
	require.Equal(t, &NormalizedRequest{
		Host:        "example.com",
		Scheme:      "http",
		Path:        "/",
		Method:      "POST",
		Body:        "{'a':'test-body'}",
		QueryValues: map[string][]string{"a": []string{"b"}},
		Headers:     map[string][]string{"Authorization": []string{"test-value"}},
		Cookies:     map[string]string{"name": "value"},
	}, normalized, "could not get correct normalized POST request")
}

func TestNormalizeNetHTTPMultipartRequest(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.com/test?a=b", nil)
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

	normalized, err := NormalizeRequest(req)
	require.Nil(t, err, "could not create normalized request")
	spew.Dump(normalized)
	//require.Equal(t, &NormalizedRequest{
	//	Host:        "example.com",
	//	Scheme:      "http",
	//	Path:        "/test",
	//	Method:      "GET",
	//	QueryValues: map[string][]string{"a": []string{"b"}},
	//	Headers:     map[string][]string{},
	//}, normalized, "could not get correct normalized GET request")

}

func TestNormalizeNetHTTPFormRequest(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.com/", nil)
	require.Nil(t, err, "could not create http request")

	form := make(url.Values)
	form.Set("name", "hacker")
	form.Set("password", "pass")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Body = ioutil.NopCloser(strings.NewReader(form.Encode()))

	normalized, err := NormalizeRequest(req)
	require.Nil(t, err, "could not create normalized request")
	spew.Dump(normalized)
	//require.Equal(t, &NormalizedRequest{
	//	Host:        "example.com",
	//	Scheme:      "http",
	//	Path:        "/test",
	//	Method:      "GET",
	//	QueryValues: map[string][]string{"a": []string{"b"}},
	//	Headers:     map[string][]string{},
	//}, normalized, "could not get correct normalized GET request")

}

func TestNormalizeNetHTTPJSONRequest(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.com/", strings.NewReader(`
	{
		"name": {"first": "Tom", "last": "Anderson"},
		"children": ["Sara","Alex","Jack"],
		"friends": [
			{"first": "Dale", "last": "Murphy", "age": 44, "nets": ["ig", "fb", "tw"]},
		]
	}`))
	require.Nil(t, err, "could not create http request")
	req.Header.Set("Content-Type", "application/json")

	normalized, err := NormalizeRequest(req)
	require.Nil(t, err, "could not create normalized request")
	spew.Dump(normalized)
	//require.Equal(t, &NormalizedRequest{
	//	Host:        "example.com",
	//	Scheme:      "http",
	//	Path:        "/test",
	//	Method:      "GET",
	//	QueryValues: map[string][]string{"a": []string{"b"}},
	//	Headers:     map[string][]string{},
	//}, normalized, "could not get correct normalized GET request")

}

func TestNormalizeNetHTTPXMLRequest(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.com/", strings.NewReader(`
<note>
<to>Tove</to>
<from>Jani</from>
<heading>Reminder</heading>
<body>Don't forget me this weekend!</body>
</note>`))
	require.Nil(t, err, "could not create http request")
	req.Header.Set("Content-Type", "text/xml")

	normalized, err := NormalizeRequest(req)
	require.Nil(t, err, "could not create normalized request")
	spew.Dump(normalized)
	//require.Equal(t, &NormalizedRequest{
	//	Host:        "example.com",
	//	Scheme:      "http",
	//	Path:        "/test",
	//	Method:      "GET",
	//	QueryValues: map[string][]string{"a": []string{"b"}},
	//	Headers:     map[string][]string{},
	//}, normalized, "could not get correct normalized GET request")

}
