package utils

import (
	"io"
)

var (
	MaxBodyRead = int64(1 << 22) // 4MB using shift operator
)

var _ io.ReadCloser = &LimitResponseBody{}

type LimitResponseBody struct {
	io.Reader
	io.Closer
}

// NewLimitResponseBody wraps response body with a limit reader.
// thus only allowing MaxBodyRead bytes to be read. i.e 4MB
func NewLimitResponseBody(body io.ReadCloser) io.ReadCloser {
	return NewLimitResponseBodyWithSize(body, MaxBodyRead)
}

// NewLimitResponseBody wraps response body with a limit reader.
// thus only allowing MaxBodyRead bytes to be read. i.e 4MB
func NewLimitResponseBodyWithSize(body io.ReadCloser, size int64) io.ReadCloser {
	if body == nil {
		return nil
	}
	if size == -1 {
		// stick to default 4MB
		size = MaxBodyRead
	}
	return &LimitResponseBody{
		Reader: io.LimitReader(body, size),
		Closer: body,
	}
}

// LimitBodyRead limits the body read to MaxBodyRead bytes.
func LimitBodyRead(r io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, MaxBodyRead))
}
