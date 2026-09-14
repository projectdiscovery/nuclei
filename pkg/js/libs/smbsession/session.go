package smbsession

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	gpsession "github.com/Mzack9999/goimpacket/pkg/session"
	gpsmb "github.com/Mzack9999/goimpacket/pkg/smb"

	"github.com/projectdiscovery/nuclei/v3/pkg/js/libs/gptransport"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

const (
	// DefaultMaxReadBytes caps remote file reads into memory.
	DefaultMaxReadBytes = 10 << 20 // 10 MiB
	// DefaultMaxTreeDepth caps recursive tree walks.
	DefaultMaxTreeDepth = 8
	// DefaultMaxTreeEntries caps how many tree entries are collected.
	DefaultMaxTreeEntries = 1024
)

// Creds holds NTLM (password or hash) credentials for Dial.
type Creds struct {
	User     string
	Password string
	Domain   string
	Hash     string // optional NT hash; when set, preferred over password
}

// Entry is a share-relative file or directory record.
type Entry struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	IsDir   bool   `json:"is_dir"`
	ModTime string `json:"mod_time,omitempty"`
}

// shareBackend is the subset of goimpacket SMB client used for share I/O.
// Tests substitute a fake implementation.
type shareBackend interface {
	UseShare(name string) error
	Ls(dir string) ([]os.FileInfo, error)
	Cat(file string) (string, error)
	ListShares() ([]string, error)
}

// shareOpener is an optional extension for streaming reads with a byte cap.
type shareOpener interface {
	Open(file string) (io.ReadCloser, error)
}

// Session wraps an authenticated goimpacket SMB client.
type Session struct {
	client  *gpsmb.Client
	backend shareBackend // when set (tests), used instead of client
}

// Dial connects and authenticates to host:port using the execution's dialer.
func Dial(ctx context.Context, executionID, host string, port int, creds Creds) (*Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !protocolstate.IsHostAllowed(executionID, host) {
		return nil, protocolstate.ErrHostDenied.Msgf(host)
	}
	if port <= 0 {
		port = 445
	}
	domain, user := ParseIdentity(creds.User)
	if creds.Domain != "" {
		domain = creds.Domain
	}
	if user == "" {
		user = strings.TrimSpace(creds.User)
	}

	gpCreds := &gpsession.Credentials{
		Domain:   domain,
		Username: user,
		Password: creds.Password,
		Hash:     creds.Hash,
	}
	target := gpsession.Target{Host: host, Port: port}
	client := gpsmb.NewClientWithDialer(target, gpCreds, gptransport.NewExecDialer(executionID))

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.Connect()
	}()
	select {
	case <-ctx.Done():
		client.Close()
		// Drain connect result so the goroutine can exit; ignore the outcome
		// because cancellation already won the race.
		<-errCh
		return nil, ctx.Err()
	case err := <-errCh:
		if err != nil {
			return nil, err
		}
		return &Session{client: client}, nil
	}
}

// FromClient wraps an already-connected goimpacket SMB client (e.g. dcerpc's).
func FromClient(client *gpsmb.Client) *Session {
	return &Session{client: client}
}

// Close tears down the SMB session. Safe on nil.
func (s *Session) Close() {
	if s == nil || s.client == nil {
		return
	}
	s.client.Close()
}

// Native returns the underlying goimpacket client for advanced callers.
func (s *Session) Native() *gpsmb.Client {
	if s == nil {
		return nil
	}
	return s.client
}

func (s *Session) ops() shareBackend {
	if s == nil {
		return nil
	}
	if s.backend != nil {
		return s.backend
	}
	if s.client == nil {
		return nil
	}
	return s.client
}

// ListShares enumerates share names.
func (s *Session) ListShares() ([]string, error) {
	ops := s.ops()
	if ops == nil {
		return nil, fmt.Errorf("smb session not connected")
	}
	return ops.ListShares()
}

// ListDir lists one directory on share (share-relative path).
func (s *Session) ListDir(share, dir string) ([]Entry, error) {
	ops := s.ops()
	if ops == nil {
		return nil, fmt.Errorf("smb session not connected")
	}
	return listDir(ops, share, dir)
}

// ReadFile reads a file from share, capped at maxBytes (default DefaultMaxReadBytes).
func (s *Session) ReadFile(share, filePath string, maxBytes int64) (string, error) {
	ops := s.ops()
	if ops == nil {
		return "", fmt.Errorf("smb session not connected")
	}
	return readFile(ops, share, filePath, maxBytes)
}

// ListTree walks share directories up to maxDepth / maxEntries.
func (s *Session) ListTree(share, root string, maxDepth, maxEntries int) ([]Entry, error) {
	ops := s.ops()
	if ops == nil {
		return nil, fmt.Errorf("smb session not connected")
	}
	return listTree(ops, share, root, maxDepth, maxEntries)
}

func listDir(ops shareBackend, share, dir string) ([]Entry, error) {
	if err := RequireShareName(share); err != nil {
		return nil, err
	}
	normalized, err := NormalizeSharePath(dir)
	if err != nil {
		return nil, err
	}
	if err := ops.UseShare(share); err != nil {
		return nil, fmt.Errorf("mount share %q: %w", share, err)
	}
	infos, err := ops.Ls(normalized)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(infos))
	for _, fi := range infos {
		name := fi.Name()
		if name == "." || name == ".." {
			continue
		}
		out = append(out, fileInfoToEntry(fi))
	}
	return out, nil
}

func readFile(ops shareBackend, share, filePath string, maxBytes int64) (string, error) {
	if err := RequireShareName(share); err != nil {
		return "", err
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxReadBytes
	}
	normalized, err := NormalizeSharePath(filePath)
	if err != nil {
		return "", err
	}
	if normalized == "." {
		return "", fmt.Errorf("file path cannot be empty")
	}
	if err := ops.UseShare(share); err != nil {
		return "", fmt.Errorf("mount share %q: %w", share, err)
	}
	// Prefer streaming Open+LimitReader when the backend supports it (tests /
	// future goimpacket Open). Fall back to Cat for the stock client.
	if opener, ok := ops.(shareOpener); ok {
		f, err := opener.Open(normalized)
		if err != nil {
			return "", err
		}
		defer func() { _ = f.Close() }()
		limited := io.LimitReader(f, maxBytes+1)
		body, err := io.ReadAll(limited)
		if err != nil {
			return "", err
		}
		if int64(len(body)) > maxBytes {
			return "", fmt.Errorf("file %q exceeds max read size of %d bytes", normalized, maxBytes)
		}
		return string(body), nil
	}
	body, err := ops.Cat(normalized)
	if err != nil {
		return "", err
	}
	if int64(len(body)) > maxBytes {
		return "", fmt.Errorf("file %q exceeds max read size of %d bytes", normalized, maxBytes)
	}
	return body, nil
}

func listTree(ops shareBackend, share, root string, maxDepth, maxEntries int) ([]Entry, error) {
	if err := RequireShareName(share); err != nil {
		return nil, err
	}
	if maxDepth <= 0 {
		maxDepth = DefaultMaxTreeDepth
	}
	if maxEntries <= 0 {
		maxEntries = DefaultMaxTreeEntries
	}
	normalized, err := NormalizeSharePath(root)
	if err != nil {
		return nil, err
	}
	if err := ops.UseShare(share); err != nil {
		return nil, fmt.Errorf("mount share %q: %w", share, err)
	}

	var out []Entry
	var walk func(rel string, depth int) error
	walk = func(rel string, depth int) error {
		if len(out) >= maxEntries {
			return fmt.Errorf("tree listing exceeded max entries (%d)", maxEntries)
		}
		infos, err := ops.Ls(rel)
		if err != nil {
			return err
		}
		for _, fi := range infos {
			name := fi.Name()
			if name == "." || name == ".." {
				continue
			}
			childRel := name
			if rel != "." && rel != "" {
				childRel = path.Join(rel, name)
			}
			entry := fileInfoToEntry(fi)
			entry.Name = childRel
			out = append(out, entry)
			if len(out) >= maxEntries {
				return fmt.Errorf("tree listing exceeded max entries (%d)", maxEntries)
			}
			if fi.IsDir() && depth < maxDepth {
				if err := walk(childRel, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(normalized, 1); err != nil {
		return out, err
	}
	return out, nil
}

func fileInfoToEntry(fi os.FileInfo) Entry {
	entry := Entry{Name: fi.Name(), Size: fi.Size(), IsDir: fi.IsDir()}
	if mt := fi.ModTime(); !mt.IsZero() {
		entry.ModTime = mt.UTC().Format(time.RFC3339)
	}
	return entry
}
