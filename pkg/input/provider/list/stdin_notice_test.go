package list

import (
	"bufio"
	"io"
	"testing"
	"time"
)

// waitFor fails the test if ch does not deliver within d.
func waitFor(t *testing.T, ch <-chan struct{}, d time.Duration, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(d):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestNoticeOnSilentStdin(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	notified := make(chan struct{}, 1)
	n := newNoticeReader(pr, 10*time.Millisecond, func() { notified <- struct{}{} })
	go func() { buf := make([]byte, 8); _, _ = n.Read(buf) }()
	waitFor(t, notified, 5*time.Second, "the notice on a silent stdin")
}

func TestNoNoticeWhenDataArrives(t *testing.T) {
	notified := make(chan struct{}, 1)
	// A reader that already holds data: the first Read delivers bytes, which
	// stops the timer before it can fire.
	n := newNoticeReader(stringsReader("a.example\n"), time.Hour, func() { notified <- struct{}{} })
	if _, err := io.ReadAll(n); err != nil {
		t.Fatal(err)
	}
	n.stop()
	select {
	case <-notified:
		t.Fatal("must not warn when stdin delivers data")
	default:
	}
}

// Targets that arrive after the notice are still read: the notice never
// changes what is scanned. The writer starts only after the notice fired.
func TestLateTargetsStillRead(t *testing.T) {
	pr, pw := io.Pipe()
	notified := make(chan struct{}, 1)
	n := newNoticeReader(pr, 10*time.Millisecond, func() { notified <- struct{}{} })
	go func() {
		defer func() { _ = pw.Close() }()
		select {
		case <-notified:
		case <-time.After(5 * time.Second):
			t.Error("timed out waiting for the notice before the late data")
			return
		}
		_, _ = pw.Write([]byte("a.example\nb.example\n"))
	}()
	var lines []string
	sc := bufio.NewScanner(n)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if len(lines) != 2 {
		t.Fatalf("late targets lost: %v", lines)
	}
}

type stringReader struct {
	s string
	i int
}

func stringsReader(s string) *stringReader { return &stringReader{s: s} }

func (r *stringReader) Read(p []byte) (int, error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	n := copy(p, r.s[r.i:])
	r.i += n
	return n, nil
}
