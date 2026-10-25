package http

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
)

func TestRequestIsOriginScoped(t *testing.T) {
	cases := []struct {
		name string
		req  Request
		want bool
	}{
		{name: "root", req: Request{Path: []string{"{{RootURL}}/health"}}, want: true},
		{name: "several roots", req: Request{Path: []string{"{{RootURL}}/a", "{{RootURL}}/b"}}, want: true},
		{name: "baseurl suffix", req: Request{Path: []string{"{{BaseURL}}/health"}}, want: false},
		{name: "path", req: Request{Path: []string{"{{RootURL}}{{Path}}"}}, want: false},
		{name: "mixed", req: Request{Path: []string{"{{RootURL}}/a", "{{BaseURL}}/b"}}, want: false},
		{name: "raw", req: Request{Path: []string{"{{RootURL}}/a"}, Raw: []string{"GET / HTTP/1.1\r\n\r\n"}}, want: false},
		{name: "payloads", req: Request{Path: []string{"{{RootURL}}/a"}, Payloads: map[string]interface{}{"id": []string{"1"}}}, want: false},
		{name: "fuzzing", req: Request{Path: []string{"{{RootURL}}/a"}, Fuzzing: []*fuzz.Rule{{}}}, want: false},
		{name: "body", req: Request{Path: []string{"{{RootURL}}/a"}, Body: "u={{BaseURL}}"}, want: false},
		{name: "header", req: Request{Path: []string{"{{RootURL}}/a"}, Headers: map[string]string{"Referer": "{{Path}}"}}, want: false},
		{name: "empty", req: Request{}, want: false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.req.IsOriginScoped(); got != tt.want {
				t.Fatalf("IsOriginScoped() = %v, want %v", got, tt.want)
			}
		})
	}
}
