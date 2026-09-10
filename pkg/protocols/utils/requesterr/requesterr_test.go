package requesterr

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestClassifyNil(t *testing.T) {
	kind, isTimeout := Classify(nil)
	if kind != "" || isTimeout {
		t.Fatalf("expected empty kind for nil, got kind=%s isTimeout=%v", kind, isTimeout)
	}
}

func TestClassifyTimeout(t *testing.T) {
	cases := []error{
		context.DeadlineExceeded,
		os.ErrDeadlineExceeded,
		errors.New("Client.Timeout exceeded while awaiting headers"),
		errors.New("i/o timeout"),
		errors.New("context deadline exceeded"),
	}
	for _, err := range cases {
		kind, isTimeout := Classify(err)
		if kind != KindTimeout || !isTimeout {
			t.Fatalf("expected timeout for %v, got kind=%s isTimeout=%v", err, kind, isTimeout)
		}
	}
}

func TestClassifyConnection(t *testing.T) {
	cases := []error{
		syscall.ECONNREFUSED,
		syscall.ECONNRESET,
		io.EOF,
		&net.OpError{Op: "dial", Err: errors.New("connect: connection refused")},
		errors.New("connection refused"),
		errors.New("no such host"),
		errors.New("network is unreachable"),
	}
	for _, err := range cases {
		kind, isTimeout := Classify(err)
		if kind != KindConnection || isTimeout {
			t.Fatalf("expected connection for %v, got kind=%s isTimeout=%v", err, kind, isTimeout)
		}
	}
}

func TestClassifyUnknown(t *testing.T) {
	kind, isTimeout := Classify(errors.New("something else entirely"))
	if kind != KindUnknown || isTimeout {
		t.Fatalf("expected unknown, got kind=%s isTimeout=%v", kind, isTimeout)
	}
}

func TestAnnotate(t *testing.T) {
	event := map[string]interface{}{}
	Annotate(event, context.DeadlineExceeded, 1500*time.Millisecond)
	if event["error"] == nil || event["error_type"] != string(KindTimeout) || event["timeout"] != true {
		t.Fatalf("unexpected annotate result: %#v", event)
	}
	if event["duration"].(float64) != 1.5 {
		t.Fatalf("unexpected duration: %v", event["duration"])
	}

	Annotate(nil, context.DeadlineExceeded, time.Second) // no panic
	Annotate(map[string]interface{}{}, nil, time.Second)  // no fields
}
