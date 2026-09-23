package http

import (
	"io"
	"net/http"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// zstdReadCloser composes the decoder's own io.ReadCloser (which calls
// zstd.Decoder.Close on Close) with the underlying HTTP response body so
// both are properly shut down.
//
// zstd.Decoder.Close() returns nothing (it is not an io.Closer), so wrapping
// the decoder directly in io.NopCloser silently discards the close call and
// leaves the decoder's background goroutines alive. zstd.Decoder.IOReadCloser
// is the library's intended bridge: its Close() calls Decoder.Close() and
// returns nil.
type zstdReadCloser struct {
	io.ReadCloser        // dec.IOReadCloser() — properly calls dec.Close()
	orig          io.ReadCloser // original (encoded) HTTP response body
}

// Close stops the zstd decoder (releasing its goroutines) then closes the
// original response body so the underlying connection can be reused.
func (z *zstdReadCloser) Close() error {
	_ = z.ReadCloser.Close() // always nil; stops decoder goroutines
	return z.orig.Close()
}

// fixZstdResponseBody must be called before passing a response to the utils
// ResponseChain. When Content-Encoding is "zstd" it replaces resp.Body with
// a *zstdReadCloser and strips the header.
//
// # Why this is necessary
//
// utils/http.ResponseChain.Fill() calls wrapDecodeReader which wraps the
// *zstd.Decoder in io.NopCloser. io.NopCloser.Close() is a no-op, so
// zstd.Decoder.Close() is never invoked. The klauspost/zstd decoder spawns
// background goroutines that block permanently on their output channels once
// io.LimitReader stops reading before EOF – producing a goroutine and memory
// leak (issue #7749; 50 requests -> 57 leaked goroutines, hundreds of MB).
//
// By pre-decoding here and stripping Content-Encoding, the ResponseChain
// treats resp.Body as plain data. DrainResponseBody (called at the end of
// Fill()) closes resp.Body, which is now our zstdReadCloser; that in turn
// calls zstd.Decoder.Close(), releasing all resources.
//
// Stripping Content-Encoding mirrors how Go's http.Transport transparently
// removes "Content-Encoding: gzip" when it performs automatic decompression.
func fixZstdResponseBody(resp *http.Response) *http.Response {
	if resp == nil || resp.Body == nil {
		return resp
	}
	if !strings.EqualFold(resp.Header.Get("Content-Encoding"), "zstd") {
		return resp
	}
	// WithDecoderConcurrency(1): use a synchronous decoder. A single goroutine
	// handles decompression; even with this option the decoder MUST be closed
	// (its goroutine blocks on a channel once the reader is abandoned), hence
	// the zstdReadCloser wrapper above.
	dec, err := zstd.NewReader(resp.Body, zstd.WithDecoderConcurrency(1))
	if err != nil {
		// If the decoder cannot be initialised leave the response unchanged;
		// upstream code will surface the error through its normal path.
		return resp
	}
	orig := resp.Body
	resp.Body = &zstdReadCloser{
		ReadCloser: dec.IOReadCloser(),
		orig:       orig,
	}
	// Strip the header so the utils ResponseChain does not attempt a second
	// zstd decode pass (which would fail on already-decoded data and itself
	// leak another decoder via io.NopCloser).
	resp.Header.Del("Content-Encoding")
	return resp
}
