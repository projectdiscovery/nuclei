package list

import (
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// stdinNoticeDelay is how long stdin may stay silent before nuclei says it is
// waiting, when targets were also given on the command line.
const stdinNoticeDelay = 2 * time.Second

// noticeReader calls notify once if no byte arrives within delay. It never
// changes what is read: stdin is still consumed until EOF or the read timeout,
// so targets from a slow producer (`subfinder | nuclei -u extra`) are kept.
type noticeReader struct {
	r      io.Reader
	got    atomic.Bool
	timer  *time.Timer
	stopMu sync.Once
}

func newNoticeReader(r io.Reader, delay time.Duration, notify func()) *noticeReader {
	n := &noticeReader{r: r}
	n.timer = time.AfterFunc(delay, func() {
		if !n.got.Load() {
			notify()
		}
	})
	return n
}

func (n *noticeReader) Read(p []byte) (int, error) {
	c, err := n.r.Read(p)
	if c > 0 || err != nil {
		n.got.Store(true)
		n.stop()
	}
	return c, err
}

func (n *noticeReader) stop() {
	n.stopMu.Do(func() { n.timer.Stop() })
}
