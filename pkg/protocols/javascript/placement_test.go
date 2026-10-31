package javascript

import "testing"

func TestSpeaksOnlyNonHTTP(t *testing.T) {
	cases := []struct {
		name    string
		scripts []string
		want    bool
	}{
		{"smb only", []string{`var smb = require("nuclei/smb"); smb.SMBClient()`}, true},
		{"single quotes", []string{`let c = require('nuclei/ssh');`}, true},
		{"protocol plus neutral helper", []string{`require("nuclei/bytes"); require("nuclei/mysql")`}, true},
		{"pre-condition counts too", []string{`require("nuclei/redis")`, `isPortOpen(Host, Port)`}, true},
		{"raw socket can speak HTTP", []string{`require("nuclei/net")`}, false},
		{"protocol plus raw socket", []string{`require("nuclei/smb"); require("nuclei/net")`}, false},
		{"http library", []string{`require("nuclei/http")`}, false},
		{"websocket is an HTTP upgrade", []string{`require("nuclei/websocket")`}, false},
		{"grpc runs over HTTP/2", []string{`require("nuclei/grpc")`}, false},
		{"unknown library", []string{`require("nuclei/somethingnew")`}, false},
		{"only neutral helpers", []string{`require("nuclei/bytes")`}, false},
		{"no require at all", []string{`isPortOpen(Host, Port)`}, false},
		{"non-literal module name", []string{`require("nuclei/smb"); var m = "nuclei/net"; require(m)`}, false},
		{"empty", []string{"", ""}, false},
	}
	for _, c := range cases {
		if got := speaksOnlyNonHTTP(c.scripts...); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
