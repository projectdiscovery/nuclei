package smb

import (
	"bytes"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	zgrabsmb "github.com/zmap/zgrab2/lib/smb/smb"
)

func TestParseNTLMIdentity(t *testing.T) {
	tests := []struct {
		in             string
		wantDomain     string
		wantUsername   string
	}{
		{"", "", ""},
		{"alice", "", "alice"},
		{`CORP\alice`, "CORP", "alice"},
		{`corp/alice`, "corp", "alice"},
		{"alice@corp.local", "corp.local", "alice"},
		{"  bob  ", "", "bob"},
	}
	for _, tt := range tests {
		domain, user := parseNTLMIdentity(tt.in)
		require.Equal(t, tt.wantDomain, domain, "input %q domain", tt.in)
		require.Equal(t, tt.wantUsername, user, "input %q user", tt.in)
	}
}

func TestNormalizeSharePath(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", ".", false},
		{".", ".", false},
		{"/", ".", false},
		{`\`, ".", false},
		{"docs", "docs", false},
		{`docs\a.txt`, "docs/a.txt", false},
		{"/docs/a.txt", "docs/a.txt", false},
		{"docs/../a.txt", "a.txt", false},
		{"../escape", "", true},
		{"docs/../../escape", "", true},
		{"a\x00b", "", true},
	}
	for _, tt := range tests {
		got, err := normalizeSharePath(tt.in)
		if tt.wantErr {
			require.Error(t, err, "input %q", tt.in)
			continue
		}
		require.NoError(t, err, "input %q", tt.in)
		require.Equal(t, tt.want, got, "input %q", tt.in)
	}
}

func TestRequireShareName(t *testing.T) {
	require.Error(t, requireShareName(""))
	require.Error(t, requireShareName("a/b"))
	require.Error(t, requireShareName(`a\b`))
	require.NoError(t, requireShareName("C$"))
	require.NoError(t, requireShareName("backup"))
}

func TestProtocolInfoFromLog(t *testing.T) {
	info := protocolInfoFromLog(&zgrabsmb.SMBLog{
		SupportV1: true,
		HasNTLM:   true,
		NativeOs:  "Windows",
		Version: &zgrabsmb.SMBVersions{
			Major:     3,
			Minor:     1,
			VerString: "SMB 3.1.1",
		},
		NegotiationLog: &zgrabsmb.NegotiationLog{
			DialectRevision: zgrabsmb.DialectSmb_3_1_1,
		},
	})
	require.True(t, info.SMB1Supported)
	require.True(t, info.SMB2Supported)
	require.Equal(t, "SMB 3.1.1", info.Version)
	require.Equal(t, "SMB 3.1.1", info.Dialect)
	require.True(t, info.HasNTLM)
	require.Equal(t, "Windows", info.NativeOS)
}

func TestListDirOnShare(t *testing.T) {
	fake := newFakeShare(map[string][]fakeNode{
		".": {
			{name: "a.txt", size: 3},
			{name: "docs", isDir: true},
			{name: ".", isDir: true},
			{name: "..", isDir: true},
		},
	})
	entries, err := listDirOnShare(fake, ".")
	require.NoError(t, err)
	require.Len(t, entries, 2)
	require.Equal(t, "a.txt", entries[0].Name)
	require.False(t, entries[0].IsDir)
	require.Equal(t, "docs", entries[1].Name)
	require.True(t, entries[1].IsDir)
}

func TestListDirOnShareRejectsEscape(t *testing.T) {
	_, err := listDirOnShare(newFakeShare(nil), "../etc")
	require.Error(t, err)
}

func TestReadFileOnShare(t *testing.T) {
	fake := newFakeShare(map[string][]fakeNode{
		".": {{name: "secret.txt", size: 5, content: "hello"}},
	})
	body, err := readFileOnShare(fake, "secret.txt", 1024)
	require.NoError(t, err)
	require.Equal(t, "hello", body)
}

func TestReadFileOnShareRejectsOversize(t *testing.T) {
	fake := newFakeShare(map[string][]fakeNode{
		".": {{name: "big.bin", size: 100, content: strings.Repeat("x", 100)}},
	})
	_, err := readFileOnShare(fake, "big.bin", 10)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds max read size")
}

func TestReadFileOnShareRejectsEmptyPath(t *testing.T) {
	_, err := readFileOnShare(newFakeShare(nil), ".", 10)
	require.Error(t, err)
}

func TestListTreeOnShare(t *testing.T) {
	fake := newFakeShare(map[string][]fakeNode{
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
	entries, err := listTreeOnShare(fake, ".", 3, 100)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	require.Contains(t, names, "root.txt")
	require.Contains(t, names, "docs")
	require.Contains(t, names, "docs/nested.txt")
	require.Contains(t, names, "docs/deep")
	require.Contains(t, names, "docs/deep/leaf.txt")
}

func TestListTreeOnShareRespectsMaxEntries(t *testing.T) {
	nodes := make([]fakeNode, 0, 5)
	for i := 0; i < 5; i++ {
		nodes = append(nodes, fakeNode{name: string(rune('a' + i)) + ".txt", size: 1, content: "x"})
	}
	fake := newFakeShare(map[string][]fakeNode{".": nodes})
	_, err := listTreeOnShare(fake, ".", 1, 3)
	require.Error(t, err)
	require.Contains(t, err.Error(), "max entries")
}

func TestDialectName(t *testing.T) {
	require.Equal(t, "SMB 2.1", dialectName(zgrabsmb.DialectSmb_2_1))
	require.Equal(t, "SMB 3.1.1", dialectName(zgrabsmb.DialectSmb_3_1_1))
	require.Equal(t, "", dialectName(0))
	require.Equal(t, "0x0999", dialectName(0x0999))
}

func TestJoinSharePath(t *testing.T) {
	require.Equal(t, ".", joinSharePath())
	require.Equal(t, "a/b", joinSharePath("a", "b"))
	require.Equal(t, "a/b", joinSharePath(`\a\`, `\b\`))
}

type fakeNode struct {
	name    string
	size    int64
	isDir   bool
	content string
	modTime time.Time
}

type fakeShare struct {
	dirs map[string][]fakeNode
}

func newFakeShare(dirs map[string][]fakeNode) *fakeShare {
	if dirs == nil {
		dirs = map[string][]fakeNode{}
	}
	return &fakeShare{dirs: dirs}
}

func (f *fakeShare) ReadDir(dirname string) ([]os.FileInfo, error) {
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

func (f *fakeShare) Open(name string) (shareFile, error) {
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
			return &fakeFile{node: n}, nil
		}
	}
	return nil, &os.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

func (f *fakeShare) Stat(name string) (os.FileInfo, error) {
	file, err := f.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return file.Stat()
}

func (f *fakeShare) Umount() error { return nil }

type fakeFile struct {
	node   fakeNode
	reader *bytes.Reader
}

func (f *fakeFile) Read(p []byte) (int, error) {
	if f.reader == nil {
		f.reader = bytes.NewReader([]byte(f.node.content))
	}
	return f.reader.Read(p)
}

func (f *fakeFile) Close() error { return nil }

func (f *fakeFile) Stat() (os.FileInfo, error) {
	return f.node.info(), nil
}

func (n fakeNode) info() os.FileInfo {
	mod := n.modTime
	if mod.IsZero() {
		mod = time.Unix(1, 0).UTC()
	}
	return fakeFileInfo{n: n, mod: mod}
}

type fakeFileInfo struct {
	n   fakeNode
	mod time.Time
}

func (f fakeFileInfo) Name() string       { return f.n.name }
func (f fakeFileInfo) Size() int64        { return f.n.size }
func (f fakeFileInfo) Mode() os.FileMode  { if f.n.isDir { return fs.ModeDir | 0755 }; return 0644 }
func (f fakeFileInfo) ModTime() time.Time { return f.mod }
func (f fakeFileInfo) IsDir() bool        { return f.n.isDir }
func (f fakeFileInfo) Sys() any           { return nil }
