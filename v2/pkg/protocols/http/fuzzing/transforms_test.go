package fuzzing

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTransformsPath(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com/test-1", nil)
	require.Nil(t, err, "could not create http request")

	normalized, err := NormalizeRequest(req)
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

	normalized, err := NormalizeRequest(req)
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

	normalized, err := NormalizeRequest(req)
	require.Nil(t, err, "could not create normalized request")

	values := CreateTransform(normalized, &AnalyzerOptions{
		Append: []string{"6842\"'><"},
		Parts:  []string{"query-values"},
	})
	require.EqualValues(t, []*Transform{{Part: "query-values", Key: "test", Value: "a6842\"'><"}, {Part: "query-values", Key: "ques", Value: "b6842\"'><"}}, values, "could not create query-values transform for append multiple")
}

func TestTransformsHeaders(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com/test-1?test=a", nil)
	require.Nil(t, err, "could not create http request")
	req.Header.Set("X-Real-IP", "127.0.0.1")

	normalized, err := NormalizeRequest(req)
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

func TestTransformsCookies(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com/test-1?test=a", nil)
	require.Nil(t, err, "could not create http request")
	req.Header.Set("Cookie", "x-user=admin;")

	normalized, err := NormalizeRequest(req)
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
