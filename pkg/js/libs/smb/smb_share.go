package smb

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/projectdiscovery/go-smb2"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// ShareEntry is a single file or directory on an SMB share.
type ShareEntry struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	IsDir   bool   `json:"is_dir"`
	ModTime string `json:"mod_time,omitempty"`
}

// shareFS is the subset of go-smb2.Share used by list/read helpers.
// Tests substitute a fake implementation.
type shareFS interface {
	ReadDir(dirname string) ([]os.FileInfo, error)
	Open(name string) (shareFile, error)
	Stat(name string) (os.FileInfo, error)
	Umount() error
}

type shareFile interface {
	io.Reader
	io.Closer
	Stat() (os.FileInfo, error)
}

type smb2ShareAdapter struct {
	share *smb2.Share
}

func (a *smb2ShareAdapter) ReadDir(dirname string) ([]os.FileInfo, error) {
	return a.share.ReadDir(dirname)
}

func (a *smb2ShareAdapter) Open(name string) (shareFile, error) {
	return a.share.Open(name)
}

func (a *smb2ShareAdapter) Stat(name string) (os.FileInfo, error) {
	return a.share.Stat(name)
}

func (a *smb2ShareAdapter) Umount() error {
	return a.share.Umount()
}

type sessionOptions struct {
	executionId string
	host        string
	port        int
	user        string
	password    string
	share       string
}

// withMountedShare dials the target through the execution's fastdialer,
// authenticates with NTLM, mounts share, and invokes fn.
func withMountedShare(ctx context.Context, opts sessionOptions, fn func(shareFS) error) error {
	if !protocolstate.IsHostAllowed(opts.executionId, opts.host) {
		return protocolstate.ErrHostDenied.Msgf(opts.host)
	}
	if err := requireShareName(opts.share); err != nil {
		return err
	}
	dialer := protocolstate.GetDialersWithId(opts.executionId)
	if dialer == nil {
		return fmt.Errorf("dialers not initialized for %s", opts.executionId)
	}

	conn, err := dialer.Fastdialer.Dial(ctx, "tcp", net.JoinHostPort(opts.host, fmt.Sprintf("%d", opts.port)))
	if err != nil {
		return err
	}
	defer func() {
		_ = conn.Close()
	}()

	domain, username := parseNTLMIdentity(opts.user)
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     username,
			Password: opts.password,
			Domain:   domain,
		},
	}
	session, err := d.DialContext(ctx, conn)
	if err != nil {
		return err
	}
	defer func() {
		_ = session.Logoff()
	}()

	mounted, err := session.Mount(opts.share)
	if err != nil {
		return fmt.Errorf("mount share %q: %w", opts.share, err)
	}
	mounted = mounted.WithContext(ctx)
	defer func() {
		_ = mounted.Umount()
	}()

	return fn(&smb2ShareAdapter{share: mounted})
}

func fileInfoToShareEntry(fi os.FileInfo) ShareEntry {
	entry := ShareEntry{
		Name:  fi.Name(),
		Size:  fi.Size(),
		IsDir: fi.IsDir(),
	}
	if mt := fi.ModTime(); !mt.IsZero() {
		entry.ModTime = mt.UTC().Format(time.RFC3339)
	}
	return entry
}

func listDirOnShare(share shareFS, dir string) ([]ShareEntry, error) {
	normalized, err := normalizeSharePath(dir)
	if err != nil {
		return nil, err
	}
	infos, err := share.ReadDir(normalized)
	if err != nil {
		return nil, err
	}
	out := make([]ShareEntry, 0, len(infos))
	for _, fi := range infos {
		name := fi.Name()
		if name == "." || name == ".." {
			continue
		}
		out = append(out, fileInfoToShareEntry(fi))
	}
	return out, nil
}

func readFileOnShare(share shareFS, filePath string, maxBytes int64) (string, error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxReadBytes
	}
	normalized, err := normalizeSharePath(filePath)
	if err != nil {
		return "", err
	}
	if normalized == "." {
		return "", fmt.Errorf("file path cannot be empty")
	}

	f, err := share.Open(normalized)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = f.Close()
	}()

	if stat, err := f.Stat(); err == nil && !stat.IsDir() && stat.Size() > maxBytes {
		return "", fmt.Errorf("file %q size %d exceeds max read size of %d bytes", normalized, stat.Size(), maxBytes)
	}

	limited := io.LimitReader(f, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", err
	}
	if int64(len(data)) > maxBytes {
		return "", fmt.Errorf("file %q exceeds max read size of %d bytes", normalized, maxBytes)
	}
	return string(data), nil
}

func listTreeOnShare(share shareFS, root string, maxDepth, maxEntries int) ([]ShareEntry, error) {
	if maxDepth <= 0 {
		maxDepth = defaultMaxTreeDepth
	}
	if maxEntries <= 0 {
		maxEntries = defaultMaxTreeEntries
	}
	normalized, err := normalizeSharePath(root)
	if err != nil {
		return nil, err
	}

	var out []ShareEntry
	var walk func(rel string, depth int) error
	walk = func(rel string, depth int) error {
		if len(out) >= maxEntries {
			return fmt.Errorf("tree listing exceeded max entries (%d)", maxEntries)
		}
		infos, err := share.ReadDir(rel)
		if err != nil {
			return err
		}
		for _, fi := range infos {
			name := fi.Name()
			if name == "." || name == ".." {
				continue
			}
			childRel := name
			if rel != "." {
				childRel = path.Join(rel, name)
			}
			entry := fileInfoToShareEntry(fi)
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

// joinSharePath builds a display path; used by tests.
func joinSharePath(parts ...string) string {
	cleaned := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.Trim(strings.ReplaceAll(p, `\`, `/`), `/`)
		if p == "" || p == "." {
			continue
		}
		cleaned = append(cleaned, p)
	}
	if len(cleaned) == 0 {
		return "."
	}
	return path.Join(cleaned...)
}
