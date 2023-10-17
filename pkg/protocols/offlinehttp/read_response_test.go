package offlinehttp

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
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
			fmt.Fprintf(w, "%s", `<!DOCTYPE html>
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
		defer data.Body.Close()

		b, err := httputil.DumpResponse(data, true)
		require.Nil(t, err, "could not dump response")

		respData, err := readResponseFromString(string(b))
		require.Nil(t, err, "could not read response from string")

		_, err = io.ReadAll(respData.Body)
		require.Nil(t, err, "could not read response body")

		require.Equal(t, "Google Frontend", respData.Header.Get("Server"), "could not get correct headers")

	})
}
