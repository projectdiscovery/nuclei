package replacer_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/replacer"
)

func BenchmarkReplace(b *testing.B) {
	// An HTTP request renders with about 60 values, enough that map lookups
	// hash their keys.
	values := map[string]any{"Hostname": "example.com", "token": "abc"}
	for i := range 60 {
		values["var"+strconv.Itoa(i)] = i
	}

	header := "POST /?t={{token}} HTTP/1.1\r\nHost: {{Hostname}}\r\n\r\n"

	for _, item := range []struct {
		name     string
		template string
	}{
		{name: "raw request", template: header},
		{name: "64KB JSON body", template: header + strings.Repeat(`{"k": "v", "n": [1, 2]} `, 2730)},
		{name: "64KB non-ASCII body", template: header + strings.Repeat("Привет, мир! ", 2730)},
		{name: "64KB unclosed markers", template: strings.Repeat(`{{`, 32768)},
		{name: "64KB markers closed at the end", template: strings.Repeat(`{`, 65536) + `}}`},
	} {
		b.Run(item.name, func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				replacer.Replace(item.template, values)
			}
		})
	}
}
