package interactsh

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/interactsh/pkg/settings"
	"github.com/projectdiscovery/utils/errkit"
)

// oastSource is where interaction URLs come from and where their interactions
// arrive: a registration nuclei makes with an interactsh server, or a feed of
// a registration another program owns.
type oastSource interface {
	URL() string
	StartPolling(duration time.Duration, callback client.InteractionCallback) error
	StopPolling() error
	Close() error
}

var _ oastSource = (*client.Client)(nil)

// idAlphabet is xid's base32hex, the alphabet interactsh servers match ids in.
const idAlphabet = "0123456789abcdefghijklmnopqrstuv"

// nonceAlphabet is z-base-32, the alphabet interactsh nonces are drawn from.
const nonceAlphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"

// maxFeedLine bounds one interaction line; a longer one is dropped.
const maxFeedLine = 4 << 20

// feedTailSize is how many bytes before the read offset are remembered to tell
// the file read before from one that took its place under the same inode: the
// last lines read, which a rewritten feed does not repeat at the same offset.
const feedTailSize = 4 << 10

type feedState uint8

const (
	feedIdle feedState = iota
	feedPolling
	feedStopping
	feedClosed
)

// feedSource serves a registration that another program made and polls: it
// builds interaction URLs from that registration's correlation id and domain,
// and reads the interactions the owner appends to a file, one JSON object per
// line in interactsh's format. Nuclei never talks to the interactsh server, so
// it needs neither the server's token nor the registration's private key.
type feedSource struct {
	path          string
	correlationID string
	domain        string
	nonceLength   int

	mu    sync.Mutex
	state feedState
	quit  chan struct{}
	done  chan struct{}

	// Read only by the polling goroutine.
	offset     int64
	tail       []byte // the last feedTailSize bytes before offset
	partial    []byte
	discarding bool
	fileInfo   os.FileInfo
}

func newFeedSource(path, correlationID, domain string) (*feedSource, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errkit.Wrap(err, "could not open interactsh feed")
	}
	_ = file.Close()
	return &feedSource{
		path:          path,
		correlationID: strings.ToLower(correlationID),
		domain:        strings.ToLower(strings.TrimSuffix(domain, ".")),
		nonceLength:   settings.CorrelationIdNonceLengthDefault,
	}, nil
}

// URL returns a new host name under the registration: the correlation id and a
// random nonce as one label, then the domain.
func (s *feedSource) URL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == feedClosed {
		return ""
	}
	nonce := make([]byte, s.nonceLength)
	_, _ = rand.Read(nonce)
	for i, b := range nonce {
		nonce[i] = nonceAlphabet[b&31]
	}
	return s.correlationID + string(nonce) + "." + s.domain
}

// StartPolling reads new interactions every duration and passes each one that
// belongs to the registration to callback.
func (s *feedSource) StartPolling(duration time.Duration, callback client.InteractionCallback) error {
	if duration <= 0 {
		return errors.New("poll duration must be positive")
	}
	if callback == nil {
		return errors.New("interaction callback must not be nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != feedIdle {
		if s.state == feedClosed {
			return errors.New("client is closed")
		}
		return errors.New("client is already polling")
	}
	s.state = feedPolling
	s.quit = make(chan struct{})
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(duration)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.readLogged(callback)
			case <-s.quit:
				// Whatever the owner wrote during the cooldown still counts.
				s.readLogged(callback)
				return
			}
		}
	}()
	return nil
}

// StopPolling reads the feed one last time and stops.
func (s *feedSource) StopPolling() error {
	s.mu.Lock()
	if s.state != feedPolling {
		s.mu.Unlock()
		return errors.New("client is not polling")
	}
	s.state = feedStopping
	quit, done := s.quit, s.done
	close(quit)
	s.mu.Unlock()

	<-done

	s.mu.Lock()
	s.state = feedIdle
	s.mu.Unlock()
	return nil
}

// Close stops issuing URLs. The registration and the feed belong to their
// owner, so there is nothing to deregister.
func (s *feedSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == feedPolling || s.state == feedStopping {
		return errors.New("client should stop polling before closing")
	}
	if s.state != feedIdle {
		return errors.New("client is already closed")
	}
	s.state = feedClosed
	return nil
}

func (s *feedSource) readLogged(callback client.InteractionCallback) {
	if err := s.read(callback); err != nil {
		gologger.Warning().Msgf("Could not read interactsh feed %s: %s", s.path, err)
	}
}

// read passes on the complete lines appended since the last read. A line the
// owner is still writing waits for the next read.
func (s *feedSource) read(callback client.InteractionCallback) error {
	file, err := os.Open(s.path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return err
	}
	// A new inode is a new file, but the old inode is no proof of the old
	// file: one deleted and recreated can get it back, and one truncated in
	// place keeps it, both possibly refilled past the offset by now. The bytes
	// before the offset tell those apart.
	if s.fileInfo != nil && (!os.SameFile(s.fileInfo, info) || info.Size() < s.offset || !s.tailMatches(file)) {
		// Replaced or rewritten: start over.
		s.offset, s.tail, s.partial, s.discarding = 0, nil, nil, false
	}
	s.fileInfo = info
	if _, err := file.Seek(s.offset, io.SeekStart); err != nil {
		return err
	}

	// Read only what the file held when this read began: a feed that grows as
	// fast as it is read would otherwise keep the read, and StopPolling, from
	// ever returning. Later lines wait for the next read.
	reader := bufio.NewReaderSize(io.LimitReader(file, info.Size()-s.offset), 32*1024)
	for {
		data, readErr := reader.ReadSlice('\n')
		s.offset += int64(len(data))
		if len(data) > 0 {
			s.rememberTail(data)
			s.consume(data, callback)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			if errors.Is(readErr, bufio.ErrBufferFull) {
				continue
			}
			return readErr
		}
	}
}

// tailMatches reports whether the bytes before the offset are still the ones
// read there.
func (s *feedSource) tailMatches(file *os.File) bool {
	got := make([]byte, len(s.tail))
	n, _ := file.ReadAt(got, s.offset-int64(len(s.tail)))
	return n == len(s.tail) && bytes.Equal(got, s.tail)
}

// rememberTail keeps the last feedTailSize bytes read.
func (s *feedSource) rememberTail(data []byte) {
	if len(data) >= feedTailSize {
		s.tail = append(s.tail[:0], data[len(data)-feedTailSize:]...)
		return
	}
	s.tail = append(s.tail, data...)
	if extra := len(s.tail) - feedTailSize; extra > 0 {
		s.tail = append(s.tail[:0], s.tail[extra:]...)
	}
}

func (s *feedSource) consume(data []byte, callback client.InteractionCallback) {
	if s.discarding {
		if newline := bytes.IndexByte(data, '\n'); newline >= 0 {
			s.discarding = false
			data = data[newline+1:]
		} else {
			return
		}
	}

	buf := append(s.partial, data...)
	start := 0
	for {
		newline := bytes.IndexByte(buf[start:], '\n')
		if newline < 0 {
			break
		}
		newline += start
		s.processLine(buf[start:newline], callback)
		start = newline + 1
	}

	s.partial = append(s.partial[:0], buf[start:]...)
	if len(s.partial) > maxFeedLine {
		gologger.Warning().Msgf("Dropping an interactsh feed line longer than %d bytes", maxFeedLine)
		s.partial = nil
		s.discarding = true
	}
}

func (s *feedSource) processLine(line []byte, callback client.InteractionCallback) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return
	}
	if len(line) > maxFeedLine {
		gologger.Warning().Msgf("Dropping an interactsh feed line longer than %d bytes", maxFeedLine)
		return
	}
	interaction := &server.Interaction{}
	if err := json.Unmarshal(line, interaction); err != nil {
		gologger.Verbose().Msgf("Skipping an unreadable interactsh feed line: %s", err)
		return
	}
	interaction.UniqueID = strings.ToLower(interaction.UniqueID)
	if len(interaction.UniqueID) != len(s.correlationID)+s.nonceLength ||
		!strings.HasPrefix(interaction.UniqueID, s.correlationID) ||
		strings.Trim(interaction.UniqueID[len(s.correlationID):], nonceAlphabet) != "" {
		return
	}
	callback(interaction)
}

// ValidateFeedOptions checks that feed mode is fully configured.
func ValidateFeedOptions(correlationID, domain, path string) error {
	if correlationID == "" || domain == "" || path == "" {
		return errors.New("-interactsh-correlation-id, -interactsh-domain and -interactsh-feed must be set together")
	}
	correlationID = strings.ToLower(correlationID)
	if len(correlationID) != settings.CorrelationIdLengthDefault || !containsOnly(correlationID, idAlphabet) {
		return fmt.Errorf("-interactsh-correlation-id must be %d characters of %s", settings.CorrelationIdLengthDefault, idAlphabet)
	}
	if !validFeedDomain(domain) {
		return fmt.Errorf("-interactsh-domain must be a bare domain without scheme, port or path: %q", domain)
	}
	return nil
}

func containsOnly(value, alphabet string) bool {
	for _, char := range value {
		if !strings.ContainsRune(alphabet, char) {
			return false
		}
	}
	return true
}

func validFeedDomain(domain string) bool {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if domain == "" || strings.ContainsAny(domain, ":/ \t\r\n") || strings.Contains(domain, "..") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' ||
			!containsOnly(label, "abcdefghijklmnopqrstuvwxyz0123456789-") {
			return false
		}
	}
	return true
}
