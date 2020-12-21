package race

import (
	"fmt"
	"io"
	"io/ioutil"
	"time"
)

// syncedReadCloser is compatible with io.ReadSeeker and performs
// gate-based synced writes to enable race condition testing.
type syncedReadCloser struct {
	data           []byte
	p              int64
	length         int64
	opengate       chan struct{}
	enableBlocking bool
}

func newSyncedReadCloser(r io.ReadCloser) *syncedReadCloser {
	var (
		s   syncedReadCloser
		err error
	)
	s.data, err = ioutil.ReadAll(r)
	if err != nil {
		return nil
	}
	r.Close()
	s.length = int64(len(s.data))
	s.opengate = make(chan struct{})
	s.enableBlocking = true
	return &s
}

func newOpenGateWithTimeout(r io.ReadCloser, d time.Duration) *syncedReadCloser {
	s := newSyncedReadCloser(r)
	s.OpenGateAfter(d)
	return s
}

func (s *syncedReadCloser) SetOpenGate(status bool) {
	s.enableBlocking = status
}

func (s *syncedReadCloser) OpenGate() {
	s.opengate <- struct{}{}
}

func (s *syncedReadCloser) OpenGateAfter(d time.Duration) {
	time.AfterFunc(d, func() {
		s.opengate <- struct{}{}
	})
}

func (s *syncedReadCloser) Seek(offset int64, whence int) (int64, error) {
	var err error
	switch whence {
	case io.SeekStart:
		s.p = 0
	case io.SeekCurrent:
		if s.p+offset < s.length {
			s.p += offset
			break
		}
		err = fmt.Errorf("offset is too big")
	case io.SeekEnd:
		if s.length-offset >= 0 {
			s.p = s.length - offset
			break
		}
		err = fmt.Errorf("offset is too big")
	}
	return s.p, err
}

func (s *syncedReadCloser) Read(p []byte) (n int, err error) {
	// If the data fits in the buffer blocks awaiting the sync instruction
	if s.p+int64(len(p)) >= s.length && s.enableBlocking {
		<-s.opengate
	}
	n = copy(p, s.data[s.p:])
	s.p += int64(n)
	if s.p == s.length {
		err = io.EOF
	}
	return n, err
}

func (s *syncedReadCloser) Close() error {
	return nil
}

func (s *syncedReadCloser) Len() int {
	return int(s.length)
}
