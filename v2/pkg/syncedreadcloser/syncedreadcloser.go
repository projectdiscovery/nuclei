package syncedreadcloser

import (
	"fmt"
	"io"
	"io/ioutil"
	"time"
)

// compatible with ReadSeeker
type SyncedReadCloser struct {
	data           []byte
	p              int64
	length         int64
	opengate       chan struct{}
	enableBlocking bool
}

func New(r io.ReadCloser) *SyncedReadCloser {
	var (
		s   SyncedReadCloser
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

func NewOpenGateWithTimeout(r io.ReadCloser, d time.Duration) *SyncedReadCloser {
	s := New(r)
	s.OpenGateAfter(d)

	return s
}

func (s *SyncedReadCloser) SetOpenGate(status bool) {
	s.enableBlocking = status
}

func (s *SyncedReadCloser) OpenGate() {
	s.opengate <- struct{}{}
}

func (s *SyncedReadCloser) OpenGateAfter(d time.Duration) {
	time.AfterFunc(d, func() {
		s.opengate <- struct{}{}
	})
}

func (s *SyncedReadCloser) Seek(offset int64, whence int) (int64, error) {
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

func (s *SyncedReadCloser) Read(p []byte) (n int, err error) {
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

func (s *SyncedReadCloser) Close() error {
	return nil
}

func (s *SyncedReadCloser) Len() int {
	return int(s.length)
}
