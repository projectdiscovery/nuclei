// Package httpbody provides a zero-copy, rewinding request body.
//
// retryablehttp's ReusableReadCloser tees every read into a second growing
// buffer and clones the body on every GetBody call, which multiplies the
// memory of large request bodies several times over. Body reads directly
// from one immutable slice instead, and GetBody hands out independent
// cursors over that same slice.
package httpbody

import (
	"io"
	"sync"

	"github.com/projectdiscovery/retryablehttp-go"
	convUtil "github.com/projectdiscovery/utils/conversion"
)

// Body is a request body over an immutable byte slice. Like
// ReusableReadCloser, it rewinds to the start once it returns io.EOF, since
// the retryablehttp retry loop resends the same req.Body without rewinding.
type Body struct {
	mu   sync.Mutex
	data []byte
	off  int
}

// New returns a Body reading data. data must not be modified afterwards.
func New(data []byte) *Body {
	return &Body{data: data}
}

// Read reads from the current offset and rewinds after returning io.EOF.
func (b *Body) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.off >= len(b.data) {
		b.off = 0
		return 0, io.EOF
	}
	n := copy(p, b.data[b.off:])
	b.off += n
	return n, nil
}

// Close is a no-op so the body can be sent again.
func (b *Body) Close() error {
	return nil
}

// Len returns the full length of the body.
func (b *Body) Len() int {
	return len(b.data)
}

// Bytes returns the body without copying. It must not be modified.
func (b *Body) Bytes() []byte {
	return b.data
}

// Set installs data as the request body. GetBody returns a new cursor over
// the same slice, so the transport and dumps never copy it. data must not be
// modified afterwards.
func Set(req *retryablehttp.Request, data []byte) {
	req.Body = New(data)
	req.GetBody = func() (io.ReadCloser, error) {
		return New(data), nil
	}
	req.ContentLength = int64(len(data))
}

// SetString installs s as the request body without copying it.
func SetString(req *retryablehttp.Request, s string) {
	Set(req, convUtil.Bytes(s))
}

// View returns the request body, without copying it when it was installed
// by Set. Other bodies are read from a fresh GetBody copy; a body without
// GetBody is read once and replaced by a Body over the result.
func View(req *retryablehttp.Request) ([]byte, error) {
	if req == nil || req.Body == nil {
		return nil, nil
	}
	if body, ok := req.Body.(*Body); ok {
		return body.Bytes(), nil
	}

	if req.GetBody != nil {
		fresh, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		if body, ok := fresh.(*Body); ok {
			return body.Bytes(), nil
		}
		return io.ReadAll(fresh)
	}

	data, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	contentLength := req.ContentLength
	Set(req, data)
	req.ContentLength = contentLength
	return data, nil
}
