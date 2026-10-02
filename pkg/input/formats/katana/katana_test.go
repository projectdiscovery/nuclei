package katana

import (
	"io"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/stretchr/testify/require"
)

func TestKatanaFormatName(t *testing.T) {
	require.Equal(t, "katana", New().Name())
}

func TestKatanaFormatParse(t *testing.T) {
	inputFile := "../testdata/katana.jsonl"

	file, err := os.Open(inputFile)
	require.Nilf(t, err, "error opening katana input file: %v", err)
	defer func() { _ = file.Close() }()

	var got []*types.RequestResponse
	err = New().Parse(file, func(rr *types.RequestResponse) bool {
		got = append(got, rr)
		return false
	}, inputFile)
	require.NoError(t, err)

	// 3 JSONL records + 1 bare URL line; malformed and blank lines skipped.
	require.Len(t, got, 4)

	urls := make([]string, 0, len(got))
	for _, rr := range got {
		urls = append(urls, rr.URL.String())
	}
	require.ElementsMatch(t, []string{
		"https://ginandjuice.shop/catalog/product?productId=1",
		"https://ginandjuice.shop/catalog/subscribe",
		"https://ginandjuice.shop/login",
		"https://ginandjuice.shop/about",
	}, urls)
}

func TestKatanaFormatRawRequestPreserved(t *testing.T) {
	// A POST with a captured raw request must preserve method and body.
	rr := parseSingle(t, `{"request":{"method":"POST","endpoint":"https://example.com/sub","raw":"POST /sub HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nemail=a%40b.com"}}`)
	require.Equal(t, "POST", rr.Request.Method)
	require.Equal(t, "email=a%40b.com", rr.Request.Body)
	require.Equal(t, "https://example.com/sub", rr.URL.String())
}

func TestKatanaFormatComponentSynthesis(t *testing.T) {
	// No raw request: it must be synthesized from method/endpoint/headers/body.
	rr := parseSingle(t, `{"request":{"method":"POST","endpoint":"https://example.com/login","headers":{"Content-Type":"application/json"},"body":"{\"u\":\"admin\"}"}}`)
	require.Equal(t, "POST", rr.Request.Method)
	require.Equal(t, `{"u":"admin"}`, rr.Request.Body)
	require.Equal(t, "https://example.com/login", rr.URL.String())

	built, err := rr.BuildRequest()
	require.NoError(t, err)
	require.Equal(t, "application/json", built.Header.Get("Content-Type"))
	require.Equal(t, "example.com", built.Host)
}

func TestKatanaFormatQueryParamsRetained(t *testing.T) {
	// Parameter variants must survive so the fuzzer can target them.
	rr := parseSingle(t, `{"request":{"method":"GET","endpoint":"https://example.com/p?id=1&q=2"}}`)
	require.Equal(t, "https://example.com/p?id=1&q=2", rr.URL.String())
	require.Equal(t, "GET", rr.Request.Method)
}

func TestKatanaFormatGracefulSkips(t *testing.T) {
	input := strings.Join([]string{
		"",
		"garbage",
		`{"request":null}`,
		`{"request":{"endpoint":""}}`,
		`{"request":{"method":"GET","endpoint":"https://example.com/ok"}}`,
	}, "\n")

	var got []*types.RequestResponse
	err := New().Parse(strings.NewReader(input), func(rr *types.RequestResponse) bool {
		got = append(got, rr)
		return false
	}, "test")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "https://example.com/ok", got[0].URL.String())
}

func TestKatanaFormatCallbackStops(t *testing.T) {
	input := strings.Join([]string{
		`{"request":{"method":"GET","endpoint":"https://example.com/1"}}`,
		`{"request":{"method":"GET","endpoint":"https://example.com/2"}}`,
	}, "\n")

	var count int
	err := New().Parse(strings.NewReader(input), func(_ *types.RequestResponse) bool {
		count++
		return true // request to stop after the first
	}, "test")
	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func TestKatanaFormatLargeRecord(t *testing.T) {
	largeBody := strings.Repeat("a", 10*1024*1024+1)
	input := `{"request":{"method":"POST","endpoint":"https://example.com/upload","body":"` + largeBody + `"}}`

	rr := parseSingle(t, input)
	require.Equal(t, largeBody, rr.Request.Body)
}

func TestKatanaFormatRecordSizeLimit(t *testing.T) {
	const (
		prefix = `{"request":{"method":"POST","endpoint":"https://example.com/upload","body":"`
		suffix = `"}}`
	)
	record := func(size int) string {
		return prefix + strings.Repeat("a", size-len(prefix)-len(suffix)) + suffix
	}

	// A record right at the limit is parsed, one byte over it is dropped.
	rr := parseSingle(t, record(MaxRecordSize))
	require.Len(t, rr.Request.Body, MaxRecordSize-len(prefix)-len(suffix))

	var got []*types.RequestResponse
	err := New().Parse(strings.NewReader(record(MaxRecordSize+1)), func(rr *types.RequestResponse) bool {
		got = append(got, rr)
		return false
	}, "test")
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestKatanaFormatOversizedRecordSkipped(t *testing.T) {
	// A record above the limit must be dropped while the rest of the file is
	// still parsed.
	input := io.MultiReader(
		strings.NewReader(`{"request":{"method":"POST","endpoint":"https://example.com/upload","body":"`),
		io.LimitReader(filler{}, MaxRecordSize),
		strings.NewReader("\"}}\n"+`{"request":{"method":"GET","endpoint":"https://example.com/ok"}}`),
	)

	var got []*types.RequestResponse
	err := New().Parse(input, func(rr *types.RequestResponse) bool {
		got = append(got, rr)
		return false
	}, "test")
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "https://example.com/ok", got[0].URL.String())
}

func TestKatanaFormatUnterminatedRecordIsBounded(t *testing.T) {
	// An unterminated record is drained rather than buffered, so what parsing
	// costs must not grow with how long the record is: a record sixteen times
	// over the limit may not cost measurably more than one just over it.
	small := allocsForUnterminatedRecord(t, 2*MaxRecordSize)
	large := allocsForUnterminatedRecord(t, 16*MaxRecordSize)

	require.LessOrEqual(t, large, small+MaxRecordSize,
		"draining a record 16x over the limit allocated %d bytes against %d for 2x", large, small)
}

// allocsForUnterminatedRecord reports the bytes allocated while parsing a
// record of the given size that never terminates with a newline.
func allocsForUnterminatedRecord(t *testing.T, size int64) uint64 {
	t.Helper()

	input := io.MultiReader(
		strings.NewReader(`{"request":{"method":"POST","endpoint":"https://example.com/upload","body":"`),
		io.LimitReader(filler{}, size),
	)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	var got []*types.RequestResponse
	err := New().Parse(input, func(rr *types.RequestResponse) bool {
		got = append(got, rr)
		return false
	}, "test")
	runtime.ReadMemStats(&after)

	require.NoError(t, err)
	require.Empty(t, got)

	return after.TotalAlloc - before.TotalAlloc
}

// filler is an endless source of record payload bytes, used to feed oversized
// records without materializing them in the test.
type filler struct{}

func (filler) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func parseSingle(t *testing.T, line string) *types.RequestResponse {
	t.Helper()
	var got *types.RequestResponse
	err := New().Parse(strings.NewReader(line), func(rr *types.RequestResponse) bool {
		got = rr
		return false
	}, "test")
	require.NoError(t, err)
	require.NotNil(t, got)
	return got
}
