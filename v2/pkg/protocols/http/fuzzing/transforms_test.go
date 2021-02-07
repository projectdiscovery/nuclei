package fuzzing

import (
	"bytes"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestTransformsPath(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com/test-1", nil)
	require.Nil(t, err, "could not create http request")

	newReq, err := retryablehttp.FromRequest(req)
	require.Nil(t, err, "could not create http request")

	normalized, err := NormalizeRequest(newReq)
	require.Nil(t, err, "could not create normalized request")

	values := CreateTransform(normalized, &AnalyzerOptions{
		Append: []string{"6842\"'><"},
		Parts:  []string{"path"},
	})
	require.Equal(t, []*Transform{{Part: "path", Value: "/test-1/6842\"'><"}}, values, "could not create path transform for append")

	values = CreateTransform(normalized, &AnalyzerOptions{
		Replace: []string{"6842\"'><"},
		Parts:   []string{"path"},
	})
	require.Equal(t, []*Transform{{Part: "path", Value: "/6842\"'><"}}, values, "could not create path transform for replace")
}

func TestTransformsQueryValues(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com/test-1?test=a", nil)
	require.Nil(t, err, "could not create http request")

	newReq, err := retryablehttp.FromRequest(req)
	require.Nil(t, err, "could not create http request")

	normalized, err := NormalizeRequest(newReq)
	require.Nil(t, err, "could not create normalized request")

	values := CreateTransform(normalized, &AnalyzerOptions{
		Append: []string{"6842\"'><"},
		Parts:  []string{"query-values"},
	})
	require.Equal(t, []*Transform{{Part: "query-values", Key: "test", Value: "a6842\"'><"}}, values, "could not create query-values transform for append")

	values = CreateTransform(normalized, &AnalyzerOptions{
		Replace: []string{"6842\"'><"},
		Parts:   []string{"query-values"},
	})
	require.Equal(t, []*Transform{{Part: "query-values", Key: "test", Value: "6842\"'><"}}, values, "could not create query-values transform for replace")
}

func TestTransformsQueryValuesMultiple(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com/test-1?test=a&ques=b", nil)
	require.Nil(t, err, "could not create http request")

	newReq, err := retryablehttp.FromRequest(req)
	require.Nil(t, err, "could not create http request")

	normalized, err := NormalizeRequest(newReq)
	require.Nil(t, err, "could not create normalized request")

	values := CreateTransform(normalized, &AnalyzerOptions{
		Append: []string{"6842\"'><"},
		Parts:  []string{"query-values"},
	})
	require.ElementsMatch(t, []*Transform{{Part: "query-values", Key: "test", Value: "a6842\"'><"}, {Part: "query-values", Key: "ques", Value: "b6842\"'><"}}, values, "could not create query-values transform for append multiple")
}

func TestTransformsHeaders(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com/test-1?test=a", nil)
	require.Nil(t, err, "could not create http request")
	req.Header.Set("X-Real-IP", "127.0.0.1")

	newReq, err := retryablehttp.FromRequest(req)
	require.Nil(t, err, "could not create http request")

	normalized, err := NormalizeRequest(newReq)
	require.Nil(t, err, "could not create normalized request")

	values := CreateTransform(normalized, &AnalyzerOptions{
		Append: []string{"6842\"'><"},
		Parts:  []string{"headers"},
	})
	require.Equal(t, []*Transform{{Part: "headers", Key: "X-Real-Ip", Value: "127.0.0.16842\"'><"}}, values, "could not create headers transform for append")

	values = CreateTransform(normalized, &AnalyzerOptions{
		Replace: []string{"6842\"'><"},
		Parts:   []string{"headers"},
	})
	require.Equal(t, []*Transform{{Part: "headers", Key: "X-Real-Ip", Value: "6842\"'><"}}, values, "could not create headers transform for replace")
}

func TestTransformsHeadersDefaultIgnore(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com/test-1?test=a", nil)
	require.Nil(t, err, "could not create http request")
	req.Header.Set("Access-Control-Request-Headers", "127.0.0.1")

	newReq, err := retryablehttp.FromRequest(req)
	require.Nil(t, err, "could not create http request")

	normalized, err := NormalizeRequest(newReq)
	require.Nil(t, err, "could not create normalized request")

	values := CreateTransform(normalized, &AnalyzerOptions{
		Append: []string{"6842\"'><"},
		Parts:  []string{"headers"},
	})
	require.Equal(t, []*Transform{}, values, "could not create correct headers transform for append")
}

func TestTransformsCookies(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com/test-1?test=a", nil)
	require.Nil(t, err, "could not create http request")
	req.Header.Set("Cookie", "x-user=admin;")

	newReq, err := retryablehttp.FromRequest(req)
	require.Nil(t, err, "could not create http request")

	normalized, err := NormalizeRequest(newReq)
	require.Nil(t, err, "could not create normalized request")

	values := CreateTransform(normalized, &AnalyzerOptions{
		Append: []string{"6842\"'><"},
		Parts:  []string{"cookies"},
	})
	require.Equal(t, []*Transform{{Part: "cookies", Key: "x-user", Value: "admin6842\"'><"}}, values, "could not create cookies transform for append")

	values = CreateTransform(normalized, &AnalyzerOptions{
		Replace: []string{"6842\"'><"},
		Parts:   []string{"cookies"},
	})
	require.Equal(t, []*Transform{{Part: "cookies", Key: "x-user", Value: "6842\"'><"}}, values, "could not create cookies transform for replace")
}

func TestTransformsBodyFormData(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.com/test-1", nil)
	require.Nil(t, err, "could not create http request")

	form := make(url.Values)
	form.Set("name", "hacker")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Body = ioutil.NopCloser(strings.NewReader(form.Encode()))

	newReq, err := retryablehttp.FromRequest(req)
	require.Nil(t, err, "could not create http request")

	normalized, err := NormalizeRequest(newReq)
	require.Nil(t, err, "could not create normalized request")

	values := CreateTransform(normalized, &AnalyzerOptions{
		Append: []string{"6842\"'><"},
		Parts:  []string{"body"},
	})
	require.Equal(t, []*Transform{{Part: "body", Key: "name", Value: "hacker6842\"'><"}}, values, "could not create form-body transform for append")

	values = CreateTransform(normalized, &AnalyzerOptions{
		Replace: []string{"6842\"'><"},
		Parts:   []string{"body"},
	})
	require.Equal(t, []*Transform{{Part: "body", Key: "name", Value: "6842\"'><"}}, values, "could not create form-body transform for replace")
}

func TestTransformsBodyMultipartFormData(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.com/test-1", nil)
	require.Nil(t, err, "could not create http request")

	buffer := new(bytes.Buffer)
	writer := multipart.NewWriter(buffer)
	params := map[string]string{"test": "value"}
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

	values := CreateTransform(normalized, &AnalyzerOptions{
		Append: []string{"6842\"'><"},
		Parts:  []string{"body"},
	})
	require.Equal(t, []*Transform{{Part: "body", Key: "test", Value: "value6842\"'><"}}, values, "could not create multipart-body transform for append")

	values = CreateTransform(normalized, &AnalyzerOptions{
		Replace: []string{"6842\"'><"},
		Parts:   []string{"body"},
	})
	require.Equal(t, []*Transform{{Part: "body", Key: "test", Value: "6842\"'><"}}, values, "could not create multipart-body transform for replace")
}

func TestTransformsBodyJSONData(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.com/test-1", strings.NewReader(`
	{
		"name": {"first": "Tom", "last": "Anderson"},
		"children": ["Sara"]
	}`))
	require.Nil(t, err, "could not create http request")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", "1")

	newReq, err := retryablehttp.FromRequest(req)
	require.Nil(t, err, "could not create http request")

	normalized, err := NormalizeRequest(newReq)
	require.Nil(t, err, "could not create normalized request")

	values := CreateTransform(normalized, &AnalyzerOptions{
		Append: []string{"6842\"'><"},
		Parts:  []string{"body"},
	})
	require.ElementsMatch(t, []*Transform{
		{Part: "body", Key: "name/first", Value: "Tom6842\"'><"},
		{Part: "body", Key: "name/last", Value: "Anderson6842\"'><"},
		{Part: "body", Key: "children/0", Value: "Sara6842\"'><"},
	}, values, "could not create json transform for append")
}

func TestTransformsBodyJSONDataArray(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.com/test-1", strings.NewReader(`["Sara"]`))
	require.Nil(t, err, "could not create http request")
	req.Header.Set("Content-Type", "application/json")

	newReq, err := retryablehttp.FromRequest(req)
	require.Nil(t, err, "could not create http request")

	normalized, err := NormalizeRequest(newReq)
	require.Nil(t, err, "could not create normalized request")

	values := CreateTransform(normalized, &AnalyzerOptions{
		Append: []string{"6842\"'><"},
		Parts:  []string{"body"},
	})
	require.ElementsMatch(t, []*Transform{
		{Part: "body", Key: "", Value: "Sara6842\"'><"},
	}, values, "could not create json transform for append array")
}

func TestTransformsBodyXMLData(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.com/test-1", strings.NewReader(`
	<note>
	<to>Tove</to>
	</note>`))
	require.Nil(t, err, "could not create http request")
	req.Header.Set("Content-Type", "text/xml")

	newReq, err := retryablehttp.FromRequest(req)
	require.Nil(t, err, "could not create http request")

	normalized, err := NormalizeRequest(newReq)
	require.Nil(t, err, "could not create normalized request")

	values := CreateTransform(normalized, &AnalyzerOptions{
		Append: []string{"6842\"'><"},
		Parts:  []string{"body"},
	})
	require.ElementsMatch(t, []*Transform{
		{Part: "body", Key: "note/to", Value: "Tove6842\"'><"},
	}, values, "could not create xml transform")
}
