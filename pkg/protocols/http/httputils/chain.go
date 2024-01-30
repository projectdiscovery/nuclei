package httputils

import (
	"bytes"
	"fmt"
	"net/http"
	"sync"

	protoUtil "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
)

// use buffer pool for storing response body
// and reuse it for each request
var bufPool = sync.Pool{
	New: func() any {
		// The Pool's New function should generally only return pointer
		// types, since a pointer can be put into the return interface
		// value without an allocation:
		return new(bytes.Buffer)
	},
}

// getBuffer returns a buffer from the pool
func getBuffer() *bytes.Buffer {
	return bufPool.Get().(*bytes.Buffer)
}

// putBuffer returns a buffer to the pool
func putBuffer(buf *bytes.Buffer) {
	buf.Reset()
	bufPool.Put(buf)
}

// Performance Notes:
// do not use http.Response once we create ResponseChain from it
// as this reuses buffers and saves allocations and also drains response
// body automatically.
// In required cases it can be used but should never be used for anything
// related to response body.
// Bytes.Buffer returned by getters should not be used and are only meant for convinience
// purposes like .String() or .Bytes() calls.
// Remember to call Close() on ResponseChain once you are done with it.

// ResponseChain is a response chain for a http request
// on every call to previous it returns the previous response
// if it was redirected.
type ResponseChain struct {
	headers      *bytes.Buffer
	body         *bytes.Buffer
	fullResponse *bytes.Buffer
	resp         *http.Response
	reloaded     bool // if response was reloaded to its previous redirect
}

// NewResponseChain creates a new response chain for a http request
// with a maximum body size. (if -1 stick to default 4MB)
func NewResponseChain(resp *http.Response, maxBody int64) *ResponseChain {
	if _, ok := resp.Body.(protoUtil.LimitResponseBody); !ok {
		resp.Body = protoUtil.NewLimitResponseBodyWithSize(resp.Body, maxBody)
	}
	return &ResponseChain{
		headers:      getBuffer(),
		body:         getBuffer(),
		fullResponse: getBuffer(),
		resp:         resp,
	}
}

// Response returns the current response in the chain
func (r *ResponseChain) Headers() *bytes.Buffer {
	return r.headers
}

// Body returns the current response body in the chain
func (r *ResponseChain) Body() *bytes.Buffer {
	return r.body
}

// FullResponse returns the current response in the chain
func (r *ResponseChain) FullResponse() *bytes.Buffer {
	return r.fullResponse
}

// previous updates response pointer to previous response
// if it was redirected and returns true else false
func (r *ResponseChain) Previous() bool {
	if r.resp != nil && r.resp.Request != nil && r.resp.Request.Response != nil {
		r.resp = r.resp.Request.Response
		r.reloaded = true
		return true
	}
	return false
}

// Fill buffers
func (r *ResponseChain) Fill() error {
	r.reset()
	if r.resp == nil {
		return fmt.Errorf("response is nil")
	}

	// load headers
	err := DumpResponseIntoBuffer(r.resp, false, r.headers)
	if err != nil {
		return fmt.Errorf("error dumping response headers: %s", err)
	}

	if r.resp.StatusCode != http.StatusSwitchingProtocols && !r.reloaded {
		// Note about reloaded:
		// this is a known behaviour existing from earlier version
		// when redirect is followed and operators are executed on all redirect chain
		// body of those requests is not available since its already been redirected
		// This is not a issue since redirect happens with empty body according to RFC
		// but this may be required sometimes
		// Solution: Manual redirect using dynamic matchers or hijack redirected responses
		// at transport level at replace with bytes buffer and then use it

		// load body
		err = readNNormalizeRespBody(r, r.body)
		if err != nil {
			return fmt.Errorf("error reading response body: %s", err)
		}

		// response body should not be used anymore
		// drain and close
		DrainResponseBody(r.resp)
	}

	// join headers and body
	r.fullResponse.Write(r.headers.Bytes())
	r.fullResponse.Write(r.body.Bytes())
	return nil
}

// Close the response chain and releases the buffers.
func (r *ResponseChain) Close() {
	putBuffer(r.headers)
	putBuffer(r.body)
	putBuffer(r.fullResponse)
	r.headers = nil
	r.body = nil
	r.fullResponse = nil
}

// Has returns true if the response chain has a response
func (r *ResponseChain) Has() bool {
	return r.resp != nil
}

// Request is request of current response
func (r *ResponseChain) Request() *http.Request {
	if r.resp == nil {
		return nil
	}
	return r.resp.Request
}

// Response is response of current response
func (r *ResponseChain) Response() *http.Response {
	return r.resp
}

// reset without releasing the buffers
// useful for redirect chain
func (r *ResponseChain) reset() {
	r.headers.Reset()
	r.body.Reset()
	r.fullResponse.Reset()
}
