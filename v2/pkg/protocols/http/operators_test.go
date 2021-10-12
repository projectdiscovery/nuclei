package http

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/internal/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
)

func TestResponseToDSLMap(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-http"
	request := &Request{
		ID:     templateID,
		Name:   "testing",
		Path:   []string{"{{BaseURL}}?test=1"},
		Method: "GET",
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile file request")

	resp := &http.Response{}
	resp.Header = make(http.Header)
	resp.Header.Set("Test", "Test-Response")
	host := "http://example.com/test/"
	matched := "http://example.com/test/?test=1"

	event := request.responseToDSLMap(resp, host, matched, exampleRawRequest, exampleRawResponse, exampleResponseBody, exampleResponseHeader, 1*time.Second, map[string]interface{}{})
	require.Len(t, event, 13, "could not get correct number of items in dsl map")
	require.Equal(t, exampleRawResponse, event["response"], "could not get correct resp")
	require.Equal(t, "Test-Response", event["test"], "could not get correct resp for header")
}

func TestHTTPOperatorMatch(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-http"
	request := &Request{
		ID:     templateID,
		Name:   "testing",
		Path:   []string{"{{BaseURL}}?test=1"},
		Method: "GET",
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile file request")

	resp := &http.Response{}
	resp.Header = make(http.Header)
	resp.Header.Set("Test", "Test-Response")
	host := "http://example.com/test/"
	matched := "http://example.com/test/?test=1"

	event := request.responseToDSLMap(resp, host, matched, exampleRawRequest, exampleRawResponse, exampleResponseBody, exampleResponseHeader, 1*time.Second, map[string]interface{}{})
	require.Len(t, event, 13, "could not get correct number of items in dsl map")
	require.Equal(t, exampleRawResponse, event["response"], "could not get correct resp")
	require.Equal(t, "Test-Response", event["test"], "could not get correct resp for header")

	t.Run("valid", func(t *testing.T) {
		matcher := &matchers.Matcher{
			Part:  "body",
			Type:  "word",
			Words: []string{"1.1.1.1"},
		}
		err = matcher.CompileMatchers()
		require.Nil(t, err, "could not compile matcher")

		isMatched, matched := request.Match(event, matcher)
		require.True(t, isMatched, "could not match valid response")
		require.Equal(t, matcher.Words, matched)
	})

	t.Run("negative", func(t *testing.T) {
		matcher := &matchers.Matcher{
			Part:     "body",
			Type:     "word",
			Negative: true,
			Words:    []string{"random"},
		}
		err := matcher.CompileMatchers()
		require.Nil(t, err, "could not compile negative matcher")

		isMatched, matched := request.Match(event, matcher)
		require.True(t, isMatched, "could not match valid negative response matcher")
		require.Equal(t, []string{}, matched)
	})

	t.Run("invalid", func(t *testing.T) {
		matcher := &matchers.Matcher{
			Part:  "body",
			Type:  "word",
			Words: []string{"random"},
		}
		err := matcher.CompileMatchers()
		require.Nil(t, err, "could not compile matcher")

		isMatched, matched := request.Match(event, matcher)
		require.False(t, isMatched, "could match invalid response matcher")
		require.Equal(t, []string{}, matched)
	})
}

func TestHTTPOperatorExtract(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-http"
	request := &Request{
		ID:     templateID,
		Name:   "testing",
		Path:   []string{"{{BaseURL}}?test=1"},
		Method: "GET",
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile file request")

	resp := &http.Response{}
	resp.Header = make(http.Header)
	resp.Header.Set("Test-Header", "Test-Response")
	host := "http://example.com/test/"
	matched := "http://example.com/test/?test=1"

	event := request.responseToDSLMap(resp, host, matched, exampleRawRequest, exampleRawResponse, exampleResponseBody, exampleResponseHeader, 1*time.Second, map[string]interface{}{})
	require.Len(t, event, 13, "could not get correct number of items in dsl map")
	require.Equal(t, exampleRawResponse, event["response"], "could not get correct resp")
	require.Equal(t, "Test-Response", event["test_header"], "could not get correct resp for header")

	t.Run("extract", func(t *testing.T) {
		extractor := &extractors.Extractor{
			Part:  "body",
			Type:  "regex",
			Regex: []string{"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+"},
		}
		err = extractor.CompileExtractors()
		require.Nil(t, err, "could not compile extractor")

		data := request.Extract(event, extractor)
		require.Greater(t, len(data), 0, "could not extractor valid response")
		require.Equal(t, map[string]struct{}{"1.1.1.1": {}}, data, "could not extract correct data")
	})

	t.Run("kval", func(t *testing.T) {
		extractor := &extractors.Extractor{
			Type: "kval",
			KVal: []string{"test_header"},
		}
		err = extractor.CompileExtractors()
		require.Nil(t, err, "could not compile kval extractor")

		data := request.Extract(event, extractor)
		require.Greater(t, len(data), 0, "could not extractor kval valid response")
		require.Equal(t, map[string]struct{}{"Test-Response": {}}, data, "could not extract correct kval data")
	})

	t.Run("json", func(t *testing.T) {
		event["body"] = exampleJSONResponseBody

		t.Run("jq-simple", func(t *testing.T) {
			extractor := &extractors.Extractor{
				Type: "json",
				JSON: []string{".batters | .batter | .[] | .id"},
			}
			err = extractor.CompileExtractors()
			require.Nil(t, err, "could not compile json extractor")

			data := request.Extract(event, extractor)
			require.Greater(t, len(data), 0, "could not extractor json valid response")
			require.Equal(t, map[string]struct{}{"1001": {}, "1002": {}, "1003": {}, "1004": {}}, data, "could not extract correct json data")
		})
		t.Run("jq-array", func(t *testing.T) {
			extractor := &extractors.Extractor{
				Type: "json",
				JSON: []string{".array"},
			}
			err = extractor.CompileExtractors()
			require.Nil(t, err, "could not compile json extractor")

			data := request.Extract(event, extractor)
			require.Greater(t, len(data), 0, "could not extractor json valid response")
			require.Equal(t, map[string]struct{}{"[\"hello\",\"world\"]": {}}, data, "could not extract correct json data")
		})
		t.Run("jq-object", func(t *testing.T) {
			extractor := &extractors.Extractor{
				Type: "json",
				JSON: []string{".batters"},
			}
			err = extractor.CompileExtractors()
			require.Nil(t, err, "could not compile json extractor")

			data := request.Extract(event, extractor)
			require.Greater(t, len(data), 0, "could not extractor json valid response")
			require.Equal(t, map[string]struct{}{"{\"batter\":[{\"id\":\"1001\",\"type\":\"Regular\"},{\"id\":\"1002\",\"type\":\"Chocolate\"},{\"id\":\"1003\",\"type\":\"Blueberry\"},{\"id\":\"1004\",\"type\":\"Devil's Food\"}]}": {}}, data, "could not extract correct json data")
		})
	})
}

func TestHTTPMakeResult(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-http"
	request := &Request{
		ID:     templateID,
		Name:   "testing",
		Path:   []string{"{{BaseURL}}?test=1"},
		Method: "GET",
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Name:  "test",
				Part:  "body",
				Type:  "word",
				Words: []string{"1.1.1.1"},
			}},
			Extractors: []*extractors.Extractor{{
				Part:  "body",
				Type:  "regex",
				Regex: []string{"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+"},
			}},
		},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile file request")

	resp := &http.Response{}
	resp.Header = make(http.Header)
	resp.Header.Set("Test", "Test-Response")
	host := "http://example.com/test/"
	matched := "http://example.com/test/?test=1"

	event := request.responseToDSLMap(resp, host, matched, exampleRawRequest, exampleRawResponse, exampleResponseBody, exampleResponseHeader, 1*time.Second, map[string]interface{}{})
	require.Len(t, event, 13, "could not get correct number of items in dsl map")
	require.Equal(t, exampleRawResponse, event["response"], "could not get correct resp")
	require.Equal(t, "Test-Response", event["test"], "could not get correct resp for header")

	event["ip"] = "192.169.1.1"
	finalEvent := &output.InternalWrappedEvent{InternalEvent: event}
	if request.CompiledOperators != nil {
		result, ok := request.CompiledOperators.Execute(event, request.Match, request.Extract, false)
		if ok && result != nil {
			finalEvent.OperatorsResult = result
			finalEvent.Results = request.MakeResultEvent(finalEvent)
		}
	}
	require.Equal(t, 1, len(finalEvent.Results), "could not get correct number of results")
	require.Equal(t, "test", finalEvent.Results[0].MatcherName, "could not get correct matcher name of results")
	require.Equal(t, "1.1.1.1", finalEvent.Results[0].ExtractedResults[0], "could not get correct extracted results")
}

const exampleRawRequest = `GET / HTTP/1.1
Host: example.com
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,hi;q=0.8
If-None-Match: "3147526947+gzip"
If-Modified-Since: Thu, 17 Oct 2019 07:18:26 GMT
Connection: close

`

const exampleRawResponse = exampleResponseHeader + exampleResponseBody
const exampleResponseHeader = `
HTTP/1.1 200 OK
Accept-Ranges: bytes
Age: 493322
Cache-Control: max-age=604800
Content-Type: text/html; charset=UTF-8
Date: Thu, 04 Feb 2021 12:15:51 GMT
Etag: "3147526947+ident"
Expires: Thu, 11 Feb 2021 12:15:51 GMT
Last-Modified: Thu, 17 Oct 2019 07:18:26 GMT
Server: ECS (nyb/1D1C)
Vary: Accept-Encoding
X-Cache: HIT
Content-Length: 1256
Connection: close
`

const exampleResponseBody = `
<!doctype html>
<html>
<head>
    <title>Example Domain</title>

    <meta charset="utf-8" />
    <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style type="text/css">
    body {
        background-color: #f0f0f2;
        margin: 0;
        padding: 0;
        font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;
        
    }
    div {
        width: 600px;
        margin: 5em auto;
        padding: 2em;
        background-color: #fdfdff;
        border-radius: 0.5em;
        box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);
    }
    a:link, a:visited {
        color: #38488f;
        text-decoration: none;
    }
    @media (max-width: 700px) {
        div {
            margin: 0 auto;
            width: auto;
        }
    }
    </style>    
</head>
<a>1.1.1.1</a>
<body>
<div>
    <h1>Example Domain</h1>
    <p>This domain is for use in illustrative examples in documents. You may use this
    domain in literature without prior coordination or asking for permission.</p>
    <p><a href="https://www.iana.org/domains/example">More information...</a></p>
</div>
</body>
</html>
`

const exampleJSONResponseBody = `
{
  "id": "0001",
  "type": "donut",
  "name": "Cake",
  "ppu": 0.55,
  "array": ["hello", "world"],
  "batters": {
    "batter": [
      {
        "id": "1001",
        "type": "Regular"
      },
      {
        "id": "1002",
        "type": "Chocolate"
      },
      {
        "id": "1003",
        "type": "Blueberry"
      },
      {
        "id": "1004",
        "type": "Devil's Food"
      }
    ]
  },
  "topping": [
    {
      "id": "5001",
      "type": "None"
    },
    {
      "id": "5002",
      "type": "Glazed"
    },
    {
      "id": "5005",
      "type": "Sugar"
    },
    {
      "id": "5007",
      "type": "Powdered Sugar"
    },
    {
      "id": "5006",
      "type": "Chocolate with Sprinkles"
    },
    {
      "id": "5003",
      "type": "Chocolate"
    },
    {
      "id": "5004",
      "type": "Maple"
    }
  ]
}
`
