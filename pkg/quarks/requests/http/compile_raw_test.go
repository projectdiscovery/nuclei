package http

import "testing"

func TestRawRequest(t *testing.T) {
	req := Request{
		Raw: []string{
			`GET /manager/html HTTP/1.1
			Host: {{Hostname}}
			Authorization: Basic {{base64('username:password')}}
			User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0
			Accept-Language: en-US,en;q=0.9
			Connection: close`,
		},
	}
	_, _ = req.compileRawRequests()
}
