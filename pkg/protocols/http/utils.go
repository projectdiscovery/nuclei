package http

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/httpbody"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
	convUtil "github.com/projectdiscovery/utils/conversion"
	"github.com/projectdiscovery/utils/errkit"
)

// maxCurlBodySize is the largest request body included in a curl command.
// Larger bodies are left out so the command stays readable.
const maxCurlBodySize = 4 * 1024

// requestDump is a dumped request whose body may be cut short.
type requestDump struct {
	// data holds the request line, the headers and at most maxBody bytes
	// of the body, followed by a truncation marker when cut short.
	data []byte
	// truncated is the number of body bytes left out of data.
	truncated int
}

// dump creates a dump of the http request in form of a byte slice. Only the
// first maxBody bytes of the body are kept; maxBody <= 0 keeps all of it.
func dump(req *generatedRequest, reqURL string, maxBody int) (requestDump, error) {
	if req.request != nil {
		dumped, err := dumpRequest(req.request, maxBody)
		if err != nil {
			return requestDump{}, errkit.Wrapf(err, "could not dump request: %v", req.request.String())
		}
		return dumped, nil
	}
	data := req.rawRequest.Data
	truncated := 0
	if maxBody > 0 && len(data) > maxBody {
		truncated = len(data) - maxBody
		data = data[:maxBody]
	}
	rawHttpOptions := &rawhttp.Options{CustomHeaders: req.rawRequest.UnsafeHeaders, CustomRawBytes: req.rawRequest.UnsafeRawBytes}
	bin, err := rawhttp.DumpRequestRaw(req.rawRequest.Method, reqURL, req.rawRequest.Path, generators.ExpandMapValues(req.rawRequest.Headers), io.NopCloser(strings.NewReader(data)), rawHttpOptions)
	if err != nil {
		return requestDump{}, errkit.Wrapf(err, "could not dump request: %v", reqURL)
	}
	// CustomRawBytes are dumped as given, without the body
	if len(req.rawRequest.UnsafeRawBytes) > 0 {
		truncated = 0
	}
	return requestDump{data: appendTruncationMarker(bin, truncated), truncated: truncated}, nil
}

// dumpRequest writes req the way http.Transport sends it, as
// httputil.DumpRequestOut does, but streams the body into a capped buffer
// instead of copying all of it.
func dumpRequest(req *retryablehttp.Request, maxBody int) (requestDump, error) {
	body, err := httpbody.View(req)
	if err != nil {
		return requestDump{}, err
	}
	// Use a clone to avoid a race condition with the http transport.
	clone := req.Request.Clone(req.Context())
	if len(body) == 0 {
		clone.Body = nil
		clone.ContentLength = 0
		delete(clone.Header, "Content-length")
	} else {
		clone.Body = httpbody.New(body)
		clone.ContentLength = int64(len(body))
	}
	// http.Transport writes https requests as http over its connection.
	if clone.URL != nil && clone.URL.Scheme == "https" {
		clone.URL.Scheme = "http"
	}

	capture := &cappedWriter{headerEnd: -1, maxBody: maxBody}
	if err := clone.Write(capture); err != nil {
		return requestDump{}, err
	}
	data := capture.buf
	// http.Transport asks for gzip unless the caller set an encoding.
	if clone.Header.Get("Accept-Encoding") == "" && clone.Header.Get("Range") == "" && clone.Method != http.MethodHead && capture.headerEnd >= 2 {
		end := capture.headerEnd - 2
		data = append(data[:end:end], append([]byte("Accept-Encoding: gzip\r\n"), data[end:]...)...)
	}
	return requestDump{data: appendTruncationMarker(data, capture.dropped), truncated: capture.dropped}, nil
}

func appendTruncationMarker(data []byte, truncated int) []byte {
	if truncated <= 0 {
		return data
	}
	return fmt.Appendf(data, "\n...[truncated %d bytes]", truncated)
}

// capDumpBody keeps at most maxBody bytes of the body in an already built
// request dump. maxBody <= 0 keeps the dump unchanged. Saved output and debug
// use it. Matchers keep the full dump.
func capDumpBody(dump []byte, maxBody int) []byte {
	if maxBody <= 0 {
		return dump
	}
	idx := bytes.Index(dump, headerTerminator)
	if idx < 0 {
		return dump
	}
	headerEnd := idx + len(headerTerminator)
	bodyLen := len(dump) - headerEnd
	if bodyLen <= maxBody {
		return dump
	}
	capped := append([]byte(nil), dump[:headerEnd+maxBody]...)
	return appendTruncationMarker(capped, bodyLen-maxBody)
}

var headerTerminator = []byte("\r\n\r\n")

// cappedWriter keeps the request line and headers in full and at most
// maxBody bytes of the body that follows, counting the rest.
type cappedWriter struct {
	buf       []byte
	headerEnd int
	maxBody   int
	dropped   int
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	n := len(p)
	if w.headerEnd < 0 {
		from := max(len(w.buf)-len(headerTerminator)+1, 0)
		w.buf = append(w.buf, p...)
		i := bytes.Index(w.buf[from:], headerTerminator)
		if i < 0 {
			return n, nil
		}
		w.headerEnd = from + i + len(headerTerminator)
		// re-apply the cap to body bytes that came with the headers
		p = bytes.Clone(w.buf[w.headerEnd:])
		w.buf = w.buf[:w.headerEnd]
	}
	keep := len(p)
	if w.maxBody > 0 {
		keep = min(keep, max(w.maxBody-(len(w.buf)-w.headerEnd), 0))
	}
	w.buf = append(w.buf, p[:keep]...)
	w.dropped += len(p) - keep
	return n, nil
}

// getHTTPProjectCacheScope builds the project file key for a request. A
// truncated dump does not identify the body, so its hash is added.
func getHTTPProjectCacheScope(requestDump requestDump, body []byte, scheme, host string) []byte {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	host = strings.ToLower(strings.TrimSpace(host))

	var scoped bytes.Buffer
	if scheme != "" && host != "" {
		_, _ = scoped.WriteString(scheme)
		_, _ = scoped.WriteString("://")
		_, _ = scoped.WriteString(host)
		_, _ = scoped.WriteString("\n")
	}
	_, _ = scoped.Write(requestDump.data)
	if requestDump.truncated > 0 {
		sum := sha256.Sum256(body)
		_, _ = scoped.WriteString("\nbody-sha256:")
		_, _ = scoped.WriteString(hex.EncodeToString(sum[:]))
	}
	return scoped.Bytes()
}

// body returns the request body without copying it.
func (g *generatedRequest) body() []byte {
	if g.request != nil {
		body, _ := httpbody.View(g.request)
		return body
	}
	if g.rawRequest != nil {
		return convUtil.Bytes(g.rawRequest.Data)
	}
	return nil
}
