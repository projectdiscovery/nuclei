package http

import (
	"strings"
	"testing"

	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
)

var replayBenchmarkDump []byte

func BenchmarkLargeBodyRequestStages(b *testing.B) {
	body := strings.Repeat("x", 20<<20)
	newRequest := func(b *testing.B) *retryablehttp.Request {
		b.Helper()
		request, err := retryablehttp.NewRequest("POST", "https://example.test/", body)
		if err != nil {
			b.Fatal(err)
		}
		return request
	}

	b.Run("construct", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			_ = newRequest(b)
		}
	})
	b.Run("reuse", func(b *testing.B) {
		request := newRequest(b)
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			if err := reuseRequestBody(request); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("dump", func(b *testing.B) {
		request := &generatedRequest{request: newRequest(b)}
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			var err error
			replayBenchmarkDump, err = dump(request, "https://example.test/")
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("wholePath", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			request := newRequest(b)
			if err := reuseRequestBody(request); err != nil {
				b.Fatal(err)
			}
			generated := &generatedRequest{request: request}
			for i := 0; i < 2; i++ {
				var err error
				replayBenchmarkDump, err = dump(generated, "https://example.test/")
				if err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	b.Run("wholePathReplayable", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			request, err := retryablehttp.NewRequest("POST", "https://example.test/", nil)
			if err != nil {
				b.Fatal(err)
			}
			setReplayableStringBody(request, body)
			if err := reuseRequestBody(request); err != nil {
				b.Fatal(err)
			}
			generated := &generatedRequest{request: request}
			for i := 0; i < 2; i++ {
				replayBenchmarkDump, err = dump(generated, "https://example.test/")
				if err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	b.Run("wholePathStreamed", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			source, err := NewReplayBody([]ReplayPart{{Pattern: "x", Count: 20 << 20}}, 0)
			if err != nil {
				b.Fatal(err)
			}
			request, err := retryablehttp.NewRequest("POST", "https://example.test/", nil)
			if err != nil {
				b.Fatal(err)
			}
			setReplayBody(request, source)
			if err := reuseRequestBody(request); err != nil {
				b.Fatal(err)
			}
			generated := &generatedRequest{request: request}
			for i := 0; i < 2; i++ {
				replayBenchmarkDump, err = dump(generated, "https://example.test/")
				if err != nil {
					b.Fatal(err)
				}
			}
		}
	})
}
