package offlinehttp

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"testing"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/stretchr/testify/require"
)

func TestReadResponseFromString(t *testing.T) {
	expectedBody := `<!DOCTYPE html>
<html>
<head>
<title>Firing Range</title>
</head>
<body>
   <h1>Version 0.48</h1>
   <h1>What is the Firing Range?</h1>
   <p>
</body>
</html>`

	tests := []struct {
		name string
		data string
	}{
		{
			name: "response",
			data: `HTTP/1.1 200 OK
Age: 0
Cache-Control: public, max-age=600
Content-Type: text/html
Server: Google Frontend

<!DOCTYPE html>
<html>
<head>
<title>Firing Range</title>
</head>
<body>
   <h1>Version 0.48</h1>
   <h1>What is the Firing Range?</h1>
   <p>
</body>
</html>`,
		},
		{
			name: "response-http2-without-minor-version",
			data: `HTTP/2 200 OK
Age: 0
Cache-Control: public, max-age=600
Content-Type: text/html
Server: Google Frontend

<!DOCTYPE html>
<html>
<head>
<title>Firing Range</title>
</head>
<body>
   <h1>Version 0.48</h1>
   <h1>What is the Firing Range?</h1>
   <p>
</body>
</html>`,
		},
		{
			name: "response-http2-with-minor-version",
			data: `HTTP/2.0 200 OK
Age: 0
Cache-Control: public, max-age=600
Content-Type: text/html
Server: Google Frontend

<!DOCTYPE html>
<html>
<head>
<title>Firing Range</title>
</head>
<body>
   <h1>Version 0.48</h1>
   <h1>What is the Firing Range?</h1>
   <p>
</body>
</html>`,
		},
		{
			name: "request-response",
			data: `GET http://public-firing-range.appspot.com/ HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36

HTTP/1.1 200 OK
Age: 0
Cache-Control: public, max-age=600
Content-Type: text/html
Server: Google Frontend

<!DOCTYPE html>
<html>
<head>
<title>Firing Range</title>
</head>
<body>
   <h1>Version 0.48</h1>
   <h1>What is the Firing Range?</h1>
   <p>
</body>
</html>`,
		},
		{
			name: "request-response-without-minor-version",
			data: `GET http://public-firing-range.appspot.com/ HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36

HTTP/2 200 OK
Age: 0
Cache-Control: public, max-age=600
Content-Type: text/html
Server: Google Frontend

<!DOCTYPE html>
<html>
<head>
<title>Firing Range</title>
</head>
<body>
   <h1>Version 0.48</h1>
   <h1>What is the Firing Range?</h1>
   <p>
</body>
</html>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := readResponseFromString(tt.data)
			require.Nil(t, err, "could not read response from string")

			respData, err := io.ReadAll(resp.Body)
			require.Nil(t, err, "could not read response body")
			require.Equal(t, expectedBody, string(respData), "could not get correct parsed body")
			require.Equal(t, "Google Frontend", resp.Header.Get("Server"), "could not get correct headers")
		})
	}

	t.Run("test-live-response-with-content-length", func(t *testing.T) {
		var ts *httptest.Server
		router := httprouter.New()
		router.GET("/", func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
			w.Header().Add("Server", "Google Frontend")
			_, _ = fmt.Fprintf(w, "%s", `<!DOCTYPE html>
			<html>
			<head>
			<title>Firing Range</title>
			</head>
			<body>
			   <h1>Version 0.48</h1>
			   <h1>What is the Firing Range?</h1>
			   <p>
			</body>
			</html>`)
		})
		ts = httptest.NewServer(router)
		defer ts.Close()

		client := &http.Client{
			Timeout: 3 * time.Second,
		}

		data, err := client.Get(ts.URL)
		require.Nil(t, err, "could not dial url")
		defer func() {
			_ = data.Body.Close()
		}()

		b, err := httputil.DumpResponse(data, true)
		require.Nil(t, err, "could not dump response")

		respData, err := readResponseFromString(string(b))
		require.Nil(t, err, "could not read response from string")

		_, err = io.ReadAll(respData.Body)
		require.Nil(t, err, "could not read response body")

		require.Equal(t, "Google Frontend", respData.Header.Get("Server"), "could not get correct headers")

	})
}

func TestReadResponseFromStringPreservesHTTPVersionText(t *testing.T) {
	const body = "Supports HTTP/2 and HTTP/3."

	tests := []struct {
		name       string
		data       string
		wantProto  string
		wantStatus string
		wantVia    string
		wantMethod string
	}{
		{
			name:       "body-with-content-length",
			data:       "HTTP/1.1 200 OK\r\nContent-Length: 27\r\n\r\n" + body,
			wantProto:  "HTTP/1.1",
			wantStatus: "200 OK",
		},
		{
			name:       "body-without-content-length",
			data:       "HTTP/1.1 200 OK\r\n\r\n" + body,
			wantProto:  "HTTP/1.1",
			wantStatus: "200 OK",
		},
		{
			name:       "body-with-chunked-encoding",
			data:       "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1b\r\n" + body + "\r\n0\r\n\r\n",
			wantProto:  "HTTP/1.1",
			wantStatus: "200 OK",
		},
		{
			name:       "header-value",
			data:       "HTTP/1.1 200 OK\r\nVia: HTTP/2 edge\r\nContent-Length: 27\r\n\r\n" + body,
			wantProto:  "HTTP/1.1",
			wantStatus: "200 OK",
			wantVia:    "HTTP/2 edge",
		},
		{
			name:       "reason-phrase",
			data:       "HTTP/1.1 200 Use HTTP/2 instead\r\nContent-Length: 27\r\n\r\n" + body,
			wantProto:  "HTTP/1.1",
			wantStatus: "200 Use HTTP/2 instead",
		},
		{
			name:       "status-line-without-minor-version",
			data:       "HTTP/2 200 OK\r\nVia: HTTP/2 edge\r\nContent-Length: 27\r\n\r\n" + body,
			wantProto:  "HTTP/2.0",
			wantStatus: "200 OK",
			wantVia:    "HTTP/2 edge",
		},
		{
			name:       "http3-status-line-without-minor-version",
			data:       "HTTP/3 200 OK\r\nContent-Length: 27\r\n\r\n" + body,
			wantProto:  "HTTP/3.0",
			wantStatus: "200 OK",
		},
		{
			name:       "request-then-status-line-without-minor-version",
			data:       "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nHTTP/2 200 OK\r\nContent-Length: 27\r\n\r\n" + body,
			wantProto:  "HTTP/2.0",
			wantStatus: "200 OK",
			wantMethod: "GET",
		},
		{
			name:       "blank-line-before-response",
			data:       "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 27\r\n\r\n" + body,
			wantProto:  "HTTP/1.1",
			wantStatus: "200 OK",
			wantMethod: "GET",
		},
		{
			name:       "request-with-body-then-response",
			data:       "POST /search HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nq=1HTTP/1.1 200 OK\r\nContent-Length: 27\r\n\r\n" + body,
			wantProto:  "HTTP/1.1",
			wantStatus: "200 OK",
			wantMethod: "POST",
		},
		{
			name:       "request-without-saved-body-then-response",
			data:       "POST /search HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 27\r\n\r\n" + body,
			wantProto:  "HTTP/1.1",
			wantStatus: "200 OK",
			wantMethod: "POST",
		},
		{
			name:       "request-then-interim-response",
			data:       "POST /search HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\nq=1HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 27\r\n\r\n" + body,
			wantProto:  "HTTP/1.1",
			wantStatus: "200 OK",
			wantMethod: "POST",
		},
		{
			name:       "interim-response-without-minor-version",
			data:       "HTTP/2 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\nHTTP/2 200 OK\r\nContent-Length: 27\r\n\r\n" + body,
			wantProto:  "HTTP/2.0",
			wantStatus: "200 OK",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := readResponseFromString(tt.data)
			require.NoError(t, err, "could not read response from string")

			respBody, err := io.ReadAll(resp.Body)
			require.NoError(t, err, "could not read response body")
			require.Equal(t, body, string(respBody), "could not get correct parsed body")
			require.Equal(t, tt.wantProto, resp.Proto, "could not get correct protocol")
			require.Equal(t, tt.wantStatus, resp.Status, "could not get correct status")
			require.Equal(t, tt.wantVia, resp.Header.Get("Via"), "could not get correct headers")

			var gotMethod string
			if resp.Request != nil {
				gotMethod = resp.Request.Method
			}
			require.Equal(t, tt.wantMethod, gotMethod, "could not get correct request")
		})
	}
}

func TestReadResponseFromStringInterimResponses(t *testing.T) {
	tests := []struct {
		name       string
		data       string
		wantStatus string
		wantMethod string
	}{
		{
			name:       "interim-response-only",
			data:       "HTTP/1.1 100 Continue\r\n\r\n",
			wantStatus: "100 Continue",
		},
		{
			name:       "request-then-interim-response-only",
			data:       "POST /search HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nq=1HTTP/1.1 100 Continue\r\n\r\n",
			wantStatus: "100 Continue",
			wantMethod: "POST",
		},
		{
			name:       "request-then-interim-then-final-response",
			data:       "POST /search HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\nq=1HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
			wantStatus: "200 OK",
			wantMethod: "POST",
		},
		{
			name:       "request-then-interim-then-final-response-with-status-line-in-body",
			data:       "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\nsee HTTP/1.1 404 fake\r\n\r\nx",
			wantStatus: "200 OK",
			wantMethod: "GET",
		},
		{
			name:       "request-then-interim-then-blank-line-then-final-response-with-status-line-in-body",
			data:       "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nHTTP/1.1 100 Continue\r\n\r\n\r\nHTTP/1.1 200 OK\r\n\r\nsee HTTP/1.1 404 fake\r\n\r\nx",
			wantStatus: "200 OK",
			wantMethod: "GET",
		},
		{
			name:       "too-many-interim-responses",
			data:       strings.Repeat("HTTP/2 103 Early Hints\r\n\r\n", 6) + "HTTP/2 200 OK\r\n\r\n",
			wantStatus: "103 Early Hints",
		},
		{
			name:       "request-then-interim-then-blank-line-then-final-response",
			data:       "POST /search HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\nq=1HTTP/1.1 100 Continue\r\n\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
			wantStatus: "200 OK",
			wantMethod: "POST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := readResponseFromString(tt.data)
			require.NoError(t, err, "could not read response from string")
			require.Equal(t, tt.wantStatus, resp.Status, "could not get correct status")

			var gotMethod string
			if resp.Request != nil {
				gotMethod = resp.Request.Method
			}
			require.Equal(t, tt.wantMethod, gotMethod, "could not get correct request")
		})
	}
}

func TestReadResponseFromStringStopsAtFirstResponse(t *testing.T) {
	data := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n\r\n" +
		"HTTP/1.1 301 Moved Permanently\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n" +
		"GET /next HTTP/1.1\r\nHost: example.com\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"
	resp, err := readResponseFromString(data)
	require.NoError(t, err)
	require.Equal(t, "301 Moved Permanently", resp.Status)
	require.Equal(t, "GET", resp.Request.Method)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Empty(t, body)
}

func TestReadResponseFromStringDoesNotSearchForHTTP(t *testing.T) {
	_, err := readResponseFromString("prefix HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	require.Error(t, err)
}
