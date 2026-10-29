// Package compress exposes streaming decompression to nuclei JavaScript
// templates (require('nuclei/compress')), so a template can decode a
// compressed response chunk by chunk as it reads it instead of holding the
// whole body.
package compress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/dsnet/compress/brotli"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zlib"
	"github.com/klauspost/compress/zstd"
)

// maxDecodedChunk caps the decoded bytes one call hands back, give or take
// one write from the decompressor, so a small compressed chunk that expands a
// lot never has to be held whole.
const maxDecodedChunk = 1 << 20

type pauseReason int

const (
	needInput pauseReason = iota
	outputFull
	finished
)

type (
	// Decoder decodes a compressed stream written to it in chunks. Each call
	// returns the bytes decoded so far, up to about 1 MB; call Read until it
	// returns no bytes before writing the next chunk. Memory stays bounded by
	// the format's window, at most 16 MB for brotli.
	// @example
	// ```javascript
	// const compress = require('nuclei/compress');
	// const hash = require('nuclei/hash');
	// const d = compress.NewDecoder('gzip');
	// const h = hash.New('sha256');
	// for (const chunk of chunks) {
	//   for (let out = d.Write(chunk); out.length > 0; out = d.Read()) h.Write(out);
	// }
	// for (let out = d.Close(); out.length > 0; out = d.Read()) h.Write(out);
	// log(h.Sum());
	// ```
	Decoder struct {
		ctx context.Context
		// The decode goroutine runs only between a send on resume and its
		// next send on paused (or done closing), and the template's calls run
		// only in between, so out is never touched by both at once.
		resume chan []byte
		paused chan pauseReason
		done   chan struct{}
		out    []byte

		// set by the template's calls
		state      pauseReason
		inputEnded bool

		// set by the decode goroutine
		pending []byte
		eof     bool
		err     error
	}
)

// NewDecoder returns a decoder for a Content-Encoding the HTTP engine
// decodes: gzip, deflate (zlib), br or zstd. identity and an empty encoding
// pass the bytes through unchanged.
// @example
// ```javascript
// const compress = require('nuclei/compress');
// const d = compress.NewDecoder('br');
// ```
func NewDecoder(ctx context.Context, encoding string) (*Decoder, error) {
	var open func(io.Reader) (io.Reader, func(), error)
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "gzip":
		open = func(r io.Reader) (io.Reader, func(), error) {
			zr, err := gzip.NewReader(r)
			return zr, func() {}, err
		}
	case "deflate":
		open = func(r io.Reader) (io.Reader, func(), error) {
			zr, err := zlib.NewReader(r)
			return zr, func() {}, err
		}
	case "br":
		open = func(r io.Reader) (io.Reader, func(), error) {
			br, err := brotli.NewReader(r, nil)
			return br, func() {}, err
		}
	case "zstd":
		open = func(r io.Reader) (io.Reader, func(), error) {
			// One goroutine so no background workers outlive the stream.
			zr, err := zstd.NewReader(r, zstd.WithDecoderConcurrency(1))
			if err != nil {
				return nil, nil, err
			}
			return zr, zr.Close, nil
		}
	case "", "identity":
		open = func(r io.Reader) (io.Reader, func(), error) {
			return r, func() {}, nil
		}
	default:
		return nil, fmt.Errorf("unsupported encoding %q, expected gzip, deflate, br, zstd or identity", encoding)
	}
	d := &Decoder{
		ctx:    ctx,
		resume: make(chan []byte),
		paused: make(chan pauseReason),
		done:   make(chan struct{}),
	}
	go d.run(open)
	d.wait()
	return d, nil
}

// Write decodes the next compressed chunk and returns the bytes decoded so
// far, up to about 1 MB.
// @example
// ```javascript
// const compress = require('nuclei/compress');
// const d = compress.NewDecoder('gzip');
// const out = d.Write(chunk);
// ```
func (d *Decoder) Write(chunk []byte) ([]byte, error) {
	if d.done == nil {
		return nil, errNotCreatedByNewDecoder
	}
	if d.inputEnded {
		return nil, errors.New("decoder is closed")
	}
	if d.state == outputFull {
		return nil, errors.New("decoded bytes are waiting: call Read until it returns no bytes before writing more")
	}
	if d.state == needInput && len(chunk) > 0 {
		// The goroutine may keep part of the chunk after Write returns, and
		// the template may reuse its array.
		d.resumeWith(bytes.Clone(chunk))
	}
	return d.result()
}

// Read returns more decoded bytes, up to about 1 MB. It returns no bytes once
// the decoder needs the next chunk or the stream has ended.
// @example
// ```javascript
// const compress = require('nuclei/compress');
// const d = compress.NewDecoder('gzip');
// for (let out = d.Write(chunk); out.length > 0; out = d.Read()) log(out.length);
// ```
func (d *Decoder) Read() ([]byte, error) {
	if d.done == nil {
		return nil, errNotCreatedByNewDecoder
	}
	d.advance()
	return d.result()
}

// Close ends the input and returns the last decoded bytes, up to about 1 MB;
// call Read for the rest. A stream that was cut short raises an error once
// all the bytes decoded before the cut have been returned.
// @example
// ```javascript
// const compress = require('nuclei/compress');
// const d = compress.NewDecoder('gzip');
// d.Write(chunk);
// for (let out = d.Close(); out.length > 0; out = d.Read()) log(out.length);
// ```
func (d *Decoder) Close() ([]byte, error) {
	if d.done == nil {
		return nil, errNotCreatedByNewDecoder
	}
	d.inputEnded = true
	d.advance()
	return d.result()
}

// The module also exposes Decoder as a class, and new compress.Decoder() has
// no encoding or decode goroutine.
var errNotCreatedByNewDecoder = errors.New("decoder was not created with compress.NewDecoder")

// advance runs the decode goroutine until it has bytes to hand back, waits
// for a chunk the template has not written yet, or has ended.
func (d *Decoder) advance() {
	for len(d.out) == 0 && (d.state == outputFull || d.state == needInput && d.inputEnded) {
		d.resumeWith(nil)
	}
}

// result hands back the decoded bytes, and the decode error once no bytes
// are left before it.
func (d *Decoder) result() ([]byte, error) {
	out := d.out
	d.out = nil
	if len(out) == 0 && d.state == finished {
		return nil, d.err
	}
	return out, nil
}

func (d *Decoder) resumeWith(chunk []byte) {
	select {
	case d.resume <- chunk:
		d.wait()
	case <-d.done:
		d.state = finished
	}
}

func (d *Decoder) wait() {
	select {
	case d.state = <-d.paused:
	case <-d.done:
		d.state = finished
	}
}

// run decodes on its own goroutine, pausing whenever it needs input or has
// decoded maxDecodedChunk bytes.
func (d *Decoder) run(open func(io.Reader) (io.Reader, func(), error)) {
	defer close(d.done)
	r, closeReader, err := open(decoderInput{d})
	if err != nil {
		d.err = err
		return
	}
	defer closeReader()
	_, err = io.Copy(decoderOutput{d}, r)
	d.err = err
}

// pause hands control back to the template and returns the chunk it
// resumes with, nil to continue or to end the input.
func (d *Decoder) pause(reason pauseReason) ([]byte, error) {
	select {
	case d.paused <- reason:
	case <-d.ctx.Done():
		return nil, context.Cause(d.ctx)
	}
	select {
	case chunk := <-d.resume:
		return chunk, nil
	case <-d.ctx.Done():
		return nil, context.Cause(d.ctx)
	}
}

type decoderInput struct{ d *Decoder }

func (in decoderInput) Read(p []byte) (int, error) {
	d := in.d
	for len(d.pending) == 0 {
		if d.eof {
			return 0, io.EOF
		}
		chunk, err := d.pause(needInput)
		if err != nil {
			return 0, err
		}
		if chunk == nil {
			d.eof = true
		}
		d.pending = chunk
	}
	n := copy(p, d.pending)
	d.pending = d.pending[n:]
	return n, nil
}

type decoderOutput struct{ d *Decoder }

func (out decoderOutput) Write(p []byte) (int, error) {
	d := out.d
	d.out = append(d.out, p...)
	if len(d.out) >= maxDecodedChunk {
		if _, err := d.pause(outputFull); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}
