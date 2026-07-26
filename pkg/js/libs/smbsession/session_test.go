package smbsession

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestDialDeniesExcludedHost(t *testing.T) {
	execID := "smbsession-dial-deny"
	require.NoError(t, protocolstate.Init(&types.Options{
		ExecutionId:    execID,
		ExcludeTargets: []string{"203.0.113.50"},
	}))
	t.Cleanup(func() { protocolstate.Close(execID) })

	_, err := Dial(context.Background(), execID, "203.0.113.50", 445, Creds{User: "u", Password: "p"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "203.0.113.50")
}

func TestSessionNilNotConnected(t *testing.T) {
	var s *Session
	_, err := s.ListDir("share", ".")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not connected")

	_, err = (&Session{}).ReadFile("share", "a.txt", 10)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not connected")
}

func TestListDirOnFakeBackend(t *testing.T) {
	fake := newFakeBackend(map[string][]fakeNode{
		".": {
			{name: "a.txt", size: 3, content: "abc"},
			{name: "docs", isDir: true},
			{name: ".", isDir: true},
			{name: "..", isDir: true},
		},
	})
	sess := &Session{backend: fake}
	entries, err := sess.ListDir("backup", ".")
	require.NoError(t, err)
	require.Len(t, entries, 2)
	require.Equal(t, "a.txt", entries[0].Name)
	require.False(t, entries[0].IsDir)
	require.Equal(t, "docs", entries[1].Name)
	require.True(t, entries[1].IsDir)
	require.Equal(t, "backup", fake.mounted)
}

func TestListDirRejectsEscapeAndBadShare(t *testing.T) {
	sess := &Session{backend: newFakeBackend(nil)}
	_, err := sess.ListDir("backup", "../etc")
	require.Error(t, err)
	_, err = sess.ListDir("", ".")
	require.Error(t, err)
	require.Contains(t, err.Error(), "share name cannot be empty")
}

func TestReadFileOnFakeBackend(t *testing.T) {
	fake := newFakeBackend(map[string][]fakeNode{
		".": {{name: "secret.txt", size: 5, content: "hello"}},
	})
	sess := &Session{backend: fake}
	body, err := sess.ReadFile("backup", "secret.txt", 1024)
	require.NoError(t, err)
	require.Equal(t, "hello", body)
}

func TestReadFileRejectsOversize(t *testing.T) {
	fake := newFakeBackend(map[string][]fakeNode{
		".": {{name: "big.bin", size: 100, content: strings.Repeat("x", 100)}},
	})
	sess := &Session{backend: fake}
	_, err := sess.ReadFile("backup", "big.bin", 10)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds max read size")
}

func TestReadFileRejectsEmptyPath(t *testing.T) {
	sess := &Session{backend: newFakeBackend(nil)}
	_, err := sess.ReadFile("backup", ".", 10)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot be empty")
}

func TestListTreeOnFakeBackend(t *testing.T) {
	fake := newFakeBackend(map[string][]fakeNode{
		".": {
			{name: "root.txt", size: 1, content: "r"},
			{name: "docs", isDir: true},
		},
		"docs": {
			{name: "nested.txt", size: 1, content: "n"},
			{name: "deep", isDir: true},
		},
		"docs/deep": {
			{name: "leaf.txt", size: 1, content: "l"},
		},
	})
	sess := &Session{backend: fake}
	entries, err := sess.ListTree("backup", ".", 3, 100)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	require.Contains(t, names, "root.txt")
	require.Contains(t, names, "docs")
	require.Contains(t, names, "docs/nested.txt")
	require.Contains(t, names, "docs/deep/leaf.txt")
}

func TestListTreeRespectsMaxEntries(t *testing.T) {
	nodes := make([]fakeNode, 0, 5)
	for i := 0; i < 5; i++ {
		nodes = append(nodes, fakeNode{name: string(rune('a'+i)) + ".txt", size: 1, content: "x"})
	}
	sess := &Session{backend: newFakeBackend(map[string][]fakeNode{".": nodes})}
	_, err := sess.ListTree("backup", ".", 1, 3)
	require.Error(t, err)
	require.Contains(t, err.Error(), "max entries")
}

func TestListTreeRespectsMaxDepth(t *testing.T) {
	fake := newFakeBackend(map[string][]fakeNode{
		".":         {{name: "docs", isDir: true}},
		"docs":      {{name: "deep", isDir: true}},
		"docs/deep": {{name: "leaf.txt", size: 1, content: "l"}},
	})
	sess := &Session{backend: fake}
	entries, err := sess.ListTree("backup", ".", 1, 100) // depth 1: only top-level
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	require.Contains(t, names, "docs")
	require.NotContains(t, names, "docs/deep")
	require.NotContains(t, names, "docs/deep/leaf.txt")
}

func TestListSharesOnFakeBackend(t *testing.T) {
	fake := newFakeBackend(nil)
	fake.shares = []string{"IPC$", "backup"}
	sess := &Session{backend: fake}
	names, err := sess.ListShares()
	require.NoError(t, err)
	require.Equal(t, []string{"IPC$", "backup"}, names)
}

type fakeNode struct {
	name    string
	size    int64
	isDir   bool
	content string
}

type fakeBackend struct {
	dirs    map[string][]fakeNode
	shares  []string
	mounted string
}

func newFakeBackend(dirs map[string][]fakeNode) *fakeBackend {
	if dirs == nil {
		dirs = map[string][]fakeNode{}
	}
	return &fakeBackend{dirs: dirs}
}

func (f *fakeBackend) UseShare(name string) error {
	f.mounted = name
	return nil
}

func (f *fakeBackend) ListShares() ([]string, error) {
	return append([]string(nil), f.shares...), nil
}

func (f *fakeBackend) Ls(dirname string) ([]os.FileInfo, error) {
	dirname = path.Clean(strings.Trim(strings.ReplaceAll(dirname, `\`, `/`), "/"))
	if dirname == "" {
		dirname = "."
	}
	nodes, ok := f.dirs[dirname]
	if !ok {
		return nil, &os.PathError{Op: "readdir", Path: dirname, Err: fs.ErrNotExist}
	}
	out := make([]os.FileInfo, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.info())
	}
	return out, nil
}

func (f *fakeBackend) Cat(name string) (string, error) {
	rc, err := f.Open(name)
	if err != nil {
		return "", err
	}
	defer func() { _ = rc.Close() }()
	body, err := io.ReadAll(rc)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (f *fakeBackend) Open(name string) (io.ReadCloser, error) {
	name = path.Clean(strings.Trim(strings.ReplaceAll(name, `\`, `/`), "/"))
	dir, base := path.Split(name)
	dir = strings.Trim(dir, "/")
	if dir == "" {
		dir = "."
	}
	nodes, ok := f.dirs[dir]
	if !ok {
		return nil, &os.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	for _, n := range nodes {
		if n.name == base {
			if n.isDir {
				return nil, &os.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
			}
			return io.NopCloser(strings.NewReader(n.content)), nil
		}
	}
	return nil, &os.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

func (n fakeNode) info() os.FileInfo {
	return fakeFileInfo{n: n, mod: time.Unix(1, 0).UTC()}
}

type fakeFileInfo struct {
	n   fakeNode
	mod time.Time
}

func (f fakeFileInfo) Name() string { return f.n.name }
func (f fakeFileInfo) Size() int64  { return f.n.size }
func (f fakeFileInfo) Mode() os.FileMode {
	if f.n.isDir {
		return fs.ModeDir | 0755
	}
	return 0644
}
func (f fakeFileInfo) ModTime() time.Time { return f.mod }
func (f fakeFileInfo) IsDir() bool        { return f.n.isDir }
func (f fakeFileInfo) Sys() any           { return nil }
