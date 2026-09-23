package requesterr

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

// Kind classifies a request execution error for matcher / DSL use.
type Kind string

const (
	KindTimeout    Kind = "timeout"
	KindConnection Kind = "connection"
	KindUnknown    Kind = "unknown"
)

const provenanceKey = "\x00nuclei-request-error"

var provenanceToken = &struct{ internal byte }{}

// Mark adds internal provenance that the error fields came from request execution.
// The token uses pointer identity so response-controlled fields cannot forge it.
func Mark(event map[string]interface{}) {
	if event != nil {
		event[provenanceKey] = provenanceToken
	}
}

// IsMarked reports whether an event has request-error provenance.
func IsMarked(event map[string]interface{}) bool {
	if event == nil {
		return false
	}
	return event[provenanceKey] == provenanceToken
}

// Unmark removes internal request-error provenance before an event is emitted.
func Unmark(event map[string]interface{}) {
	delete(event, provenanceKey)
}

// Classify returns the error kind and whether it is a timeout.
func Classify(err error) (Kind, bool) {
	if err == nil {
		return "", false
	}
	if isTimeoutErr(err) {
		return KindTimeout, true
	}
	if isConnectionErr(err) {
		return KindConnection, false
	}
	return KindUnknown, false
}

// Annotate adds error, error_type, timeout, and optional duration fields to an event map.
func Annotate(event map[string]interface{}, err error, duration time.Duration) {
	if event == nil || err == nil {
		return
	}
	kind, isTimeout := Classify(err)
	event["error"] = err.Error()
	event["error_type"] = string(kind)
	event["timeout"] = isTimeout
	if duration > 0 {
		event["duration"] = duration.Seconds()
	}
}

func isTimeoutErr(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "client.timeout")
}

func isConnectionErr(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "actively refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "network is unreachable") ||
		strings.Contains(msg, "broken pipe")
}
