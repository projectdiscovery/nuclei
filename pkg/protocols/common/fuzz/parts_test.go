package fuzz

import (
	"bytes"
	"github.com/projectdiscovery/retryablehttp-go"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/stretchr/testify/require"
)

func TestExecuteHeadersPartRule(t *testing.T) {
	options := &protocols.ExecutorOptions{
		Interactsh: &interactsh.Client{},
	}
	req, err := retryablehttp.NewRequest("GET", "http://localhost:8080/", nil)
	require.NoError(t, err, "can't build request")

	req.Header.Set("X-Custom-Foo", "foo")
	req.Header.Set("X-Custom-Bar", "bar")

	t.Run("single", func(t *testing.T) {
		rule := &Rule{
			ruleType: postfixRuleType,
			partType: headersPartType,
			modeType: singleModeType,
			options:  options,
		}
		var generatedHeaders []http.Header
		err := rule.executeHeadersPartRule(&ExecuteRuleInput{
			Input:       contextargs.New(),
			BaseRequest: req,
			Callback: func(gr GeneratedRequest) bool {
				generatedHeaders = append(generatedHeaders, gr.Request.Header.Clone())
				return true
			},
		}, "1337'")
		require.NoError(t, err, "could not execute part rule")
		require.ElementsMatch(t, []http.Header{
			{
				"X-Custom-Foo": {"foo1337'"},
				"X-Custom-Bar": {"bar"},
			},
			{
				"X-Custom-Foo": {"foo"},
				"X-Custom-Bar": {"bar1337'"},
			},
		}, generatedHeaders, "could not get generated headers")
	})

	t.Run("multiple", func(t *testing.T) {
		rule := &Rule{
			ruleType: postfixRuleType,
			partType: headersPartType,
			modeType: multipleModeType,
			options:  options,
		}
		var generatedHeaders http.Header
		err := rule.executeHeadersPartRule(&ExecuteRuleInput{
			Input:       contextargs.New(),
			BaseRequest: req,
			Callback: func(gr GeneratedRequest) bool {
				generatedHeaders = gr.Request.Header.Clone()
				return true
			},
		}, "1337'")
		require.NoError(t, err, "could not execute part rule")
		require.Equal(t, http.Header{
			"X-Custom-Foo": {"foo1337'"},
			"X-Custom-Bar": {"bar1337'"},
		}, generatedHeaders, "could not get generated headers")
	})
}
func TestExecuteQueryPartRule(t *testing.T) {
	options := &protocols.ExecutorOptions{
		Interactsh: &interactsh.Client{},
	}
	URL := "http://localhost:8080/?url=localhost&mode=multiple&file=passwdfile"
	req, err := retryablehttp.NewRequest("GET", URL, nil)
	require.NoError(t, err, "can't build request")
	t.Run("single", func(t *testing.T) {
		rule := &Rule{
			ruleType: postfixRuleType,
			partType: queryPartType,
			modeType: singleModeType,
			options:  options,
		}
		var generatedURL []string
		err := rule.executeQueryPartRule(&ExecuteRuleInput{
			Input:       contextargs.New(),
			BaseRequest: req,
			Callback: func(gr GeneratedRequest) bool {
				generatedURL = append(generatedURL, gr.Request.URL.String())
				return true
			},
		}, "1337'")
		require.NoError(t, err, "could not execute part rule")
		require.ElementsMatch(t, []string{
			"http://localhost:8080/?url=localhost1337'&mode=multiple&file=passwdfile",
			"http://localhost:8080/?url=localhost&mode=multiple1337'&file=passwdfile",
			"http://localhost:8080/?url=localhost&mode=multiple&file=passwdfile1337'",
		}, generatedURL, "could not get generated url")
	})
	t.Run("multiple", func(t *testing.T) {
		rule := &Rule{
			ruleType: postfixRuleType,
			partType: queryPartType,
			modeType: multipleModeType,
			options:  options,
		}
		var generatedURL string
		err := rule.executeQueryPartRule(&ExecuteRuleInput{
			Input:       contextargs.New(),
			BaseRequest: req,
			Callback: func(gr GeneratedRequest) bool {
				generatedURL = gr.Request.URL.String()
				return true
			},
		}, "1337'")
		require.NoError(t, err, "could not execute part rule")
		require.Equal(t, "http://localhost:8080/?url=localhost1337'&mode=multiple1337'&file=passwdfile1337'", generatedURL, "could not get generated url")
	})
}

func TestExecuteReplaceRule(t *testing.T) {
	tests := []struct {
		ruleType    ruleType
		value       string
		replacement string
		expected    string
	}{
		{replaceRuleType, "test", "replacement", "replacement"},
		{prefixRuleType, "test", "prefix", "prefixtest"},
		{postfixRuleType, "test", "postfix", "testpostfix"},
		{infixRuleType, "", "infix", "infix"},
		{infixRuleType, "0", "infix", "0infix"},
		{infixRuleType, "test", "infix", "teinfixst"},
	}
	for _, test := range tests {
		rule := &Rule{ruleType: test.ruleType}
		returned := rule.executeReplaceRule(nil, test.value, test.replacement)
		require.Equal(t, test.expected, returned, "could not get correct value")
	}
}

func TestExecuteBodyPartRule(t *testing.T) {
	options := &protocols.ExecutorOptions{
		Interactsh: &interactsh.Client{},
	}
	req, err := retryablehttp.NewRequest("POST", "http://localhost:8080/", nil)
	require.NoError(t, err, "can't build request")

	// Test for form encoded body single-mode
	t.Run("form-encoded-body-single", func(t *testing.T) {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		body := "key1=value1&key2=value2"
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
		req.Body = io.NopCloser(strings.NewReader(body))

		rule := &Rule{
			ruleType: postfixRuleType,
			partType: bodyPartType,
			modeType: singleModeType,
			options:  options,
		}
		var generatedBodies []string
		err := rule.executeBodyPartRule(&ExecuteRuleInput{
			Input:       contextargs.New(),
			BaseRequest: req,
			Callback: func(gr GeneratedRequest) bool {
				bodyBytes, _ := io.ReadAll(gr.Request.Body)
				_ = gr.Request.Body.Close()
				req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // reset the "read-once" type body for future read
				generatedBodies = append(generatedBodies, string(bodyBytes))
				return true
			},
		}, "1337")
		require.NoError(t, err, "could not execute body part rule for form-encoded")

		expectedBodies := []string{
			"key1=value11337&key2=value2", // Fuzzed key1
			"key1=value1&key2=value21337", // Fuzzed key2
		}
		require.ElementsMatch(t, expectedBodies, generatedBodies, "bodies did not match expected fuzzed bodies")
	})

	// Test for form encoded body multiple-mode
	t.Run("form-encoded-body-multiple", func(t *testing.T) {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		body := "key1=value1&key2=value2"
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
		req.Body = io.NopCloser(strings.NewReader(body))

		rule := &Rule{
			ruleType: postfixRuleType,
			partType: bodyPartType,
			modeType: multipleModeType,
			options:  options,
		}
		var generatedBodies []string
		err := rule.executeBodyPartRule(&ExecuteRuleInput{
			Input:       contextargs.New(),
			BaseRequest: req,
			Callback: func(gr GeneratedRequest) bool {
				bodyBytes, _ := io.ReadAll(gr.Request.Body)
				_ = gr.Request.Body.Close()
				req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // reset the "read-once" type body for future read
				generatedBodies = append(generatedBodies, string(bodyBytes))
				return true
			},
		}, "1337")
		require.NoError(t, err, "could not execute body part rule for form-encoded")

		expectedBodies := []string{
			"key1=value11337&key2=value21337", // Fuzzed key1 & key2
		}
		require.ElementsMatch(t, expectedBodies, generatedBodies, "bodies did not match expected fuzzed bodies")
	})

	// Test for json body single-mode
	t.Run("json-body-single", func(t *testing.T) {
		req.Header.Set("Content-Type", "application/json")
		body := "{\"key1\":\"def\",\"key2\":true,\"key3\":[1,\"2\"],\"key4\":{\"key5\":\"aaa\",\"key6\":{\"key7\":[\"bbb\", \"ccc\"]}}}"
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
		req.Body = io.NopCloser(strings.NewReader(body))

		rule := &Rule{
			ruleType: postfixRuleType,
			partType: bodyPartType,
			modeType: singleModeType,
			options:  options,
		}
		var generatedBodies []string
		err := rule.executeBodyPartRule(&ExecuteRuleInput{
			Input:       contextargs.New(),
			BaseRequest: req,
			Callback: func(gr GeneratedRequest) bool {
				bodyBytes, _ := io.ReadAll(gr.Request.Body)
				_ = gr.Request.Body.Close()
				req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // reset the "read-once" type body for future read
				generatedBodies = append(generatedBodies, string(bodyBytes))
				return true
			},
		}, "1337")
		require.NoError(t, err, "could not execute body part rule for json body")

		expectedBodies := []string{
			"{\"key1\":\"def1337\",\"key2\":true,\"key3\":[1,\"2\"],\"key4\":{\"key5\":\"aaa\",\"key6\":{\"key7\":[\"bbb\",\"ccc\"]}}}", // Fuzzed key1
			"{\"key1\":\"def\",\"key2\":true,\"key3\":[1,\"21337\"],\"key4\":{\"key5\":\"aaa\",\"key6\":{\"key7\":[\"bbb\",\"ccc\"]}}}", // Fuzzed key3[0]
			"{\"key1\":\"def\",\"key2\":true,\"key3\":[1,\"2\"],\"key4\":{\"key5\":\"aaa1337\",\"key6\":{\"key7\":[\"bbb\",\"ccc\"]}}}", // Fuzzed key4.key5
			"{\"key1\":\"def\",\"key2\":true,\"key3\":[1,\"2\"],\"key4\":{\"key5\":\"aaa\",\"key6\":{\"key7\":[\"bbb1337\",\"ccc\"]}}}", // Fuzzed key6.key7[0]
			"{\"key1\":\"def\",\"key2\":true,\"key3\":[1,\"2\"],\"key4\":{\"key5\":\"aaa\",\"key6\":{\"key7\":[\"bbb\",\"ccc1337\"]}}}", // Fuzzed key6.key7[1]
		}
		require.ElementsMatch(t, expectedBodies, generatedBodies, "bodies did not match expected fuzzed bodies")
	})

	// Test for json body single-mode
	t.Run("json-body-multiple", func(t *testing.T) {
		req.Header.Set("Content-Type", "application/json")
		body := "{\"key1\":\"def\",\"key2\":true,\"key3\":[1,\"2\"],\"key4\":{\"key5\":\"aaa\",\"key6\":{\"key7\":[\"bbb\", \"ccc\"]}}}"
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
		req.Body = io.NopCloser(strings.NewReader(body))

		rule := &Rule{
			ruleType: postfixRuleType,
			partType: bodyPartType,
			modeType: multipleModeType,
			options:  options,
		}
		var generatedBodies []string
		err := rule.executeBodyPartRule(&ExecuteRuleInput{
			Input:       contextargs.New(),
			BaseRequest: req,
			Callback: func(gr GeneratedRequest) bool {
				bodyBytes, _ := io.ReadAll(gr.Request.Body)
				_ = gr.Request.Body.Close()
				req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // reset the "read-once" type body for future read
				generatedBodies = append(generatedBodies, string(bodyBytes))
				return true
			},
		}, "1337")
		require.NoError(t, err, "could not execute body part rule for json body")

		expectedBodies := []string{
			// Fuzzed key1, key3[0], key4.key5, key6.key7[0] & key6.key7[1] together
			"{\"key1\":\"def1337\",\"key2\":true,\"key3\":[1,\"21337\"],\"key4\":{\"key5\":\"aaa1337\",\"key6\":{\"key7\":[\"bbb1337\",\"ccc1337\"]}}}",
		}
		require.ElementsMatch(t, expectedBodies, generatedBodies, "bodies did not match expected fuzzed bodies")
	})

	// Test for graphql request with referenced variables (content-type: application/json) single-mode
	t.Run("graphql-body-single", func(t *testing.T) {
		req.URL.Path = "/graphql"
		req.Header.Set("Content-Type", "application/json")
		body := "{\"query\":\"mutation SetMessage($msg: String!, $name: String!) { setMessage(message: $msg, name: $name) }\",\"variables\":{\"msg\":\"Hello, GraphQL!\",\"name\":\"Nikoo\"}}"
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
		req.Body = io.NopCloser(strings.NewReader(body))

		rule := &Rule{
			ruleType: postfixRuleType,
			partType: bodyPartType,
			modeType: singleModeType,
			options:  options,
		}
		var generatedBodies []string
		err := rule.executeBodyPartRule(&ExecuteRuleInput{
			Input:       contextargs.New(),
			BaseRequest: req,
			Callback: func(gr GeneratedRequest) bool {
				bodyBytes, _ := io.ReadAll(gr.Request.Body)
				_ = gr.Request.Body.Close()
				req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // reset the "read-once" type body for future read
				generatedBodies = append(generatedBodies, string(bodyBytes))
				return true
			},
		}, "1337")
		require.NoError(t, err, "could not execute body part rule for graphql body")

		expectedBodies := []string{
			"{\"query\":\"mutation SetMessage($msg: String!, $name: String!) { setMessage(message: $msg, name: $name) }\",\"variables\":{\"msg\":\"Hello, GraphQL!1337\",\"name\":\"Nikoo\"}}",
			"{\"query\":\"mutation SetMessage($msg: String!, $name: String!) { setMessage(message: $msg, name: $name) }\",\"variables\":{\"msg\":\"Hello, GraphQL!\",\"name\":\"Nikoo1337\"}}",
		}
		require.ElementsMatch(t, expectedBodies, generatedBodies, "bodies did not match expected fuzzed bodies")
	})

	// Test for graphql request with referenced variables (content-type: application/json) multiple-mode
	t.Run("graphql-body-multiple", func(t *testing.T) {
		req.URL.Path = "/graphql"
		req.Header.Set("Content-Type", "application/json")
		body := "{\"query\":\"mutation SetMessage($msg: String!, $name: String!) { setMessage(message: $msg, name: $name) }\",\"variables\":{\"msg\":\"Hello, GraphQL!\",\"name\":\"Nikoo\"}}"
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
		req.Body = io.NopCloser(strings.NewReader(body))

		rule := &Rule{
			ruleType: postfixRuleType,
			partType: bodyPartType,
			modeType: multipleModeType,
			options:  options,
		}
		var generatedBodies []string
		err := rule.executeBodyPartRule(&ExecuteRuleInput{
			Input:       contextargs.New(),
			BaseRequest: req,
			Callback: func(gr GeneratedRequest) bool {
				bodyBytes, _ := io.ReadAll(gr.Request.Body)
				_ = gr.Request.Body.Close()
				req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // reset the "read-once" type body for future read
				generatedBodies = append(generatedBodies, string(bodyBytes))
				return true
			},
		}, "1337")
		require.NoError(t, err, "could not execute body part rule for graphql body")

		expectedBodies := []string{
			"{\"query\":\"mutation SetMessage($msg: String!, $name: String!) { setMessage(message: $msg, name: $name) }\",\"variables\":{\"msg\":\"Hello, GraphQL!1337\",\"name\":\"Nikoo1337\"}}",
		}
		require.ElementsMatch(t, expectedBodies, generatedBodies, "bodies did not match expected fuzzed bodies")
	})

	// Test for graphql request with referenced variables (content-type: application/json) multiple-mode
	t.Run("negative-graphql-body-multiple", func(t *testing.T) {
		req.URL.Path = "/notgraphql"
		req.Header.Set("Content-Type", "application/json")
		body := "{\"query\":\"mutation SetMessage($msg: String!, $name: String!) { setMessage(message: $msg, name: $name) }\",\"variables\":{\"msg\":\"Hello, GraphQL!\",\"name\":\"Nikoo\"}}"
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
		req.Body = io.NopCloser(strings.NewReader(body))

		rule := &Rule{
			ruleType: postfixRuleType,
			partType: bodyPartType,
			modeType: multipleModeType,
			options:  options,
		}
		var generatedBodies []string
		err := rule.executeBodyPartRule(&ExecuteRuleInput{
			Input:       contextargs.New(),
			BaseRequest: req,
			Callback: func(gr GeneratedRequest) bool {
				bodyBytes, _ := io.ReadAll(gr.Request.Body)
				_ = gr.Request.Body.Close()
				req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // reset the "read-once" type body for future read
				generatedBodies = append(generatedBodies, string(bodyBytes))
				return true
			},
		}, "1337")
		require.NoError(t, err, "could not execute body part rule for not graphql request")

		expectedBodies := []string{
			"{\"query\":\"mutation SetMessage($msg: String!, $name: String!) { setMessage(message: $msg, name: $name) }1337\",\"variables\":{\"msg\":\"Hello, GraphQL!1337\",\"name\":\"Nikoo1337\"}}",
		}
		require.ElementsMatch(t, expectedBodies, generatedBodies, "bodies did not match expected fuzzed bodies")

		unwantedBodies := []string{
			"{\"query\":\"mutation SetMessage($msg: String!, $name: String!) { setMessage(message: $msg, name: $name) }\",\"variables\":{\"msg\":\"Hello, GraphQL!1337\",\"name\":\"Nikoo1337\"}}",
		}
		for _, generatedBody := range generatedBodies {
			for _, unwantedBody := range unwantedBodies {
				require.NotEqual(t, unwantedBody, generatedBody, "generated body matches an unwanted body")
			}
		}

	})

}

func TestExecuteAllPartsRule(t *testing.T) {
	options := &protocols.ExecutorOptions{
		Interactsh: &interactsh.Client{},
	}

	// Test for all parts with form encoded body in multiple-mode
	t.Run("all-parts-form-encoded-body-multiple", func(t *testing.T) {
		req, err := retryablehttp.NewRequest("POST", "http://localhost:8080/?url=localhost&mode=multiple&file=passwdfile", nil)
		require.NoError(t, err, "can't build request")
		req.Header.Set("X-Custom-Foo", "foo")
		req.Header.Set("X-Custom-Bar", "bar")

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		body := "key1=value1&key2=value2"
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
		req.Body = io.NopCloser(strings.NewReader(body))

		rule := &Rule{
			ruleType: postfixRuleType,
			partType: allPartType,
			modeType: multipleModeType,
			options:  options,
		}

		var generatedURLs []string
		var generatedHeaders []http.Header
		var generatedBodies []string

		err = rule.executeAllPartRule(&ExecuteRuleInput{
			Input:       contextargs.New(),
			BaseRequest: req,
			Callback: func(gr GeneratedRequest) bool {
				bodyBytes, _ := io.ReadAll(gr.Request.Body)
				_ = gr.Request.Body.Close()
				req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // set the body again for future read
				generatedURLs = append(generatedURLs, gr.Request.URL.String())

				generatedHeaders = append(generatedHeaders, gr.Request.Header.Clone())
				generatedBodies = append(generatedBodies, string(bodyBytes))
				return true
			},
		}, "1337")
		require.NoError(t, err, "could not execute all part rule for form-encoded")

		expectedURLs := []string{
			"http://localhost:8080/?url=localhost1337&mode=multiple1337&file=passwdfile1337", // Fuzzed url
			"http://localhost:8080/?url=localhost1337&mode=multiple1337&file=passwdfile1337", // Fuzzed mode
			"http://localhost:8080/?url=localhost1337&mode=multiple1337&file=passwdfile1337", // Fuzzed file
		}
		expectedHeaders := []http.Header{
			{
				"X-Custom-Foo":   {"foo"},
				"X-Custom-Bar":   {"bar"},
				"Content-Type":   {"application/x-www-form-urlencoded"},
				"Content-Length": {"23"},
			},
			{
				"X-Custom-Foo":   {"foo"},
				"X-Custom-Bar":   {"bar"},
				"Content-Type":   {"application/x-www-form-urlencoded"},
				"Content-Length": {"31"},
			},
			{
				"X-Custom-Foo":   {"foo1337"},
				"X-Custom-Bar":   {"bar1337"},
				"Content-Type":   {"application/x-www-form-urlencoded1337"},
				"Content-Length": {"231337"},
			},
		}
		expectedBodies := []string{
			"key1=value1&key2=value2",
			"key1=value1&key2=value2",
			"key1=value11337&key2=value21337",
		}
		require.ElementsMatch(t, expectedURLs, generatedURLs, "URL did not match expected fuzzed bodies")
		require.ElementsMatch(t, expectedHeaders, generatedHeaders, "headers did not match expected fuzzed bodies")
		require.ElementsMatch(t, expectedBodies, generatedBodies, "bodies did not match expected fuzzed bodies")
	})

	// Test for all parts with json body in multiple-mode
	t.Run("all-parts-json-body-multiple", func(t *testing.T) {
		req, err := retryablehttp.NewRequest("POST", "http://localhost:8080/?url=localhost&mode=multiple&file=passwdfile", nil)
		require.NoError(t, err, "can't build request")
		req.Header.Set("X-Custom-Foo", "foo")
		req.Header.Set("X-Custom-Bar", "bar")
		req.Header.Set("Content-Type", "application/json")

		body := "{\"key1\":\"def\",\"key2\":true,\"key3\":[1,\"2\"],\"key4\":{\"key5\":\"aaa\",\"key6\":{\"key7\":[\"bbb\", \"ccc\"]}}}"
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
		req.Body = io.NopCloser(strings.NewReader(body))

		rule := &Rule{
			ruleType: postfixRuleType,
			partType: allPartType,
			modeType: multipleModeType,
			options:  options,
		}

		var generatedURLs []string
		var generatedHeaders []http.Header
		var generatedBodies []string

		err = rule.executeAllPartRule(&ExecuteRuleInput{
			Input:       contextargs.New(),
			BaseRequest: req,
			Callback: func(gr GeneratedRequest) bool {
				bodyBytes, _ := io.ReadAll(gr.Request.Body)
				_ = gr.Request.Body.Close()
				req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // reset the "read-once" type body for future read

				generatedURLs = append(generatedURLs, gr.Request.URL.String())
				generatedHeaders = append(generatedHeaders, gr.Request.Header.Clone())
				generatedBodies = append(generatedBodies, string(bodyBytes))
				return true
			},
		}, "1337")
		require.NoError(t, err, "could not execute body part rule for json body")

		expectedURLs := []string{
			"http://localhost:8080/?url=localhost1337&mode=multiple1337&file=passwdfile1337", // Fuzzed url
			"http://localhost:8080/?url=localhost1337&mode=multiple1337&file=passwdfile1337", // Fuzzed mode
			"http://localhost:8080/?url=localhost1337&mode=multiple1337&file=passwdfile1337", // Fuzzed file
		}
		expectedHeaders := []http.Header{
			{
				"X-Custom-Foo":   {"foo"},
				"X-Custom-Bar":   {"bar"},
				"Content-Type":   {"application/json"},
				"Content-Length": {"94"},
			},
			{
				"X-Custom-Foo":   {"foo"},
				"X-Custom-Bar":   {"bar"},
				"Content-Type":   {"application/json"},
				"Content-Length": {"113"},
			},
			{
				"X-Custom-Foo":   {"foo1337"},
				"X-Custom-Bar":   {"bar1337"},
				"Content-Type":   {"application/json1337"},
				"Content-Length": {"941337"},
			},
		}

		expectedBodies := []string{
			"{\"key1\":\"def\",\"key2\":true,\"key3\":[1,\"2\"],\"key4\":{\"key5\":\"aaa\",\"key6\":{\"key7\":[\"bbb\", \"ccc\"]}}}",
			"{\"key1\":\"def\",\"key2\":true,\"key3\":[1,\"2\"],\"key4\":{\"key5\":\"aaa\",\"key6\":{\"key7\":[\"bbb\", \"ccc\"]}}}",
			"{\"key1\":\"def1337\",\"key2\":true,\"key3\":[1,\"21337\"],\"key4\":{\"key5\":\"aaa1337\",\"key6\":{\"key7\":[\"bbb1337\",\"ccc1337\"]}}}",
		}

		require.ElementsMatch(t, expectedURLs, generatedURLs, "URL did not match expected fuzzed bodies")
		require.ElementsMatch(t, expectedHeaders, generatedHeaders, "headers did not match expected fuzzed bodies")
		require.ElementsMatch(t, expectedBodies, generatedBodies, "bodies did not match expected fuzzed bodies")
	})

	// Test for all parts with graphql request body with referenced variables (content-type: application/json) in multiple-mode
	t.Run("all-parts-graphql-body-multiple", func(t *testing.T) {
		req, err := retryablehttp.NewRequest("POST", "http://localhost:8080/graphql?url=localhost&mode=multiple&file=passwdfile", nil)
		require.NoError(t, err, "can't build request")
		req.Header.Set("X-Custom-Foo", "foo")
		req.Header.Set("X-Custom-Bar", "bar")
		req.Header.Set("Content-Type", "application/json")
		body := "{\"query\":\"mutation SetMessage($msg: String!, $name: String!) { setMessage(message: $msg, name: $name) }\",\"variables\":{\"msg\":\"Hello, GraphQL!\",\"name\":\"Nikoo\"}}"
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
		req.Body = io.NopCloser(strings.NewReader(body))

		rule := &Rule{
			ruleType: postfixRuleType,
			partType: allPartType,
			modeType: multipleModeType,
			options:  options,
		}

		var generatedURLs []string
		var generatedHeaders []http.Header
		var generatedBodies []string

		err = rule.executeAllPartRule(&ExecuteRuleInput{
			Input:       contextargs.New(),
			BaseRequest: req,
			Callback: func(gr GeneratedRequest) bool {
				bodyBytes, _ := io.ReadAll(gr.Request.Body)
				_ = gr.Request.Body.Close()
				req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // reset the "read-once" type body for future read

				generatedURLs = append(generatedURLs, gr.Request.URL.String())
				generatedHeaders = append(generatedHeaders, gr.Request.Header.Clone())
				generatedBodies = append(generatedBodies, string(bodyBytes))
				return true
			},
		}, "1337")
		require.NoError(t, err, "could not execute body part rule for graphql body")

		expectedURLs := []string{
			"http://localhost:8080/graphql?url=localhost1337&mode=multiple1337&file=passwdfile1337", // Fuzzed url
			"http://localhost:8080/graphql?url=localhost1337&mode=multiple1337&file=passwdfile1337", // Fuzzed mode
			"http://localhost:8080/graphql?url=localhost1337&mode=multiple1337&file=passwdfile1337", // Fuzzed file
		}
		expectedHeaders := []http.Header{
			{
				"X-Custom-Foo":   {"foo1337"},
				"X-Custom-Bar":   {"bar1337"},
				"Content-Type":   {"application/json1337"},
				"Content-Length": {"1581337"},
			},
			{
				"X-Custom-Foo":   {"foo"},
				"X-Custom-Bar":   {"bar"},
				"Content-Type":   {"application/json"},
				"Content-Length": {"158"},
			},
			{
				"X-Custom-Foo":   {"foo"},
				"X-Custom-Bar":   {"bar"},
				"Content-Type":   {"application/json"},
				"Content-Length": {"166"},
			},
		}

		expectedBodies := []string{
			"{\"query\":\"mutation SetMessage($msg: String!, $name: String!) { setMessage(message: $msg, name: $name) }\",\"variables\":{\"msg\":\"Hello, GraphQL!\",\"name\":\"Nikoo\"}}",
			"{\"query\":\"mutation SetMessage($msg: String!, $name: String!) { setMessage(message: $msg, name: $name) }\",\"variables\":{\"msg\":\"Hello, GraphQL!\",\"name\":\"Nikoo\"}}",
			"{\"query\":\"mutation SetMessage($msg: String!, $name: String!) { setMessage(message: $msg, name: $name) }\",\"variables\":{\"msg\":\"Hello, GraphQL!1337\",\"name\":\"Nikoo1337\"}}",
		}

		require.ElementsMatch(t, expectedURLs, generatedURLs, "URL did not match expected fuzzed bodies")
		require.ElementsMatch(t, expectedHeaders, generatedHeaders, "headers did not match expected fuzzed bodies")
		require.ElementsMatch(t, expectedBodies, generatedBodies, "bodies did not match expected fuzzed bodies")
	})

}
