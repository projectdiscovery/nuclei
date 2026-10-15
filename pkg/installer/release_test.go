package installer

import (
	"bytes"
	"io"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	updateutils "github.com/projectdiscovery/utils/update"
	"github.com/stretchr/testify/require"
)

// fakeTemplateRelease is an in-memory nuclei-templates release, mapping paths
// to contents.
type fakeTemplateRelease struct {
	version string
	files   map[string]string
}

func (r fakeTemplateRelease) fetch() (templateRelease, error) { return r, nil }

func (r fakeTemplateRelease) Version() string   { return r.version }
func (r fakeTemplateRelease) Changelog() string { return "" }

func (r fakeTemplateRelease) DownloadSource(_ bool, callback updateutils.AssetFileCallback) error {
	for _, name := range slices.Sorted(maps.Keys(r.files)) {
		contents := r.files[name]
		// a github zipball nests every entry under one root directory
		uri := "projectdiscovery-nuclei-templates-test/" + name
		if err := callback(uri, fakeFileInfo{name: name, size: int64(len(contents))}, strings.NewReader(contents)); err != nil {
			return err
		}
	}
	return nil
}

// installedTemplateRelease is a release that is already installed, so
// downloading it fails the test.
type installedTemplateRelease struct {
	fakeTemplateRelease
	t *testing.T
}

// DownloadSource fails the test since the release is already installed.
func (r installedTemplateRelease) DownloadSource(bool, updateutils.AssetFileCallback) error {
	r.t.Fatalf("downloaded already installed templates %s", r.version)
	return nil
}

type fakeFileInfo struct {
	name string
	size int64
}

func (f fakeFileInfo) Name() string       { return filepath.Base(f.name) }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() fs.FileMode  { return 0o644 }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

// TestGithubTemplateHead checks the version of the head and that it downloads
// the exact head commit.
func TestGithubTemplateHead(t *testing.T) {
	commit := "3de629d823bb6eb00aa3769edc365b6525134fb1"
	entry := "projectdiscovery-nuclei-templates-3de629d/http/head.yaml"
	var fetchedRef string
	head := githubTemplateHead{
		release: fakeTemplateRelease{version: "v10.3.1"},
		commit:  commit,
		fetchArchive: func(ref string) (*bytes.Reader, error) {
			fetchedRef = ref
			return newTemplateReleaseArchive(t, entry, []byte("id: head")), nil
		},
	}

	require.Equal(t, "v10.3.1+3de629d", head.Version())
	// build metadata is ignored, so only a newer release outdates the head
	require.False(t, config.IsOutdatedVersion(head.Version(), "v10.3.1"))
	require.True(t, config.IsOutdatedVersion(head.Version(), "v10.3.2"))

	var entries []string
	require.NoError(t, head.DownloadSource(false, func(uri string, _ fs.FileInfo, _ io.Reader) error {
		entries = append(entries, uri)
		return nil
	}))
	require.Equal(t, commit, fetchedRef, "should download the exact head commit")
	require.Equal(t, []string{entry}, entries)
}

// TestTemplateVersionRef checks the git ref of release and latest channel
// versions.
func TestTemplateVersionRef(t *testing.T) {
	require.Equal(t, "v10.3.1", templateVersionRef("v10.3.1"))
	require.Equal(t, "3de629d", templateVersionRef("v10.3.1+3de629d"))
	require.Equal(t, "v10.3.1+", templateVersionRef("v10.3.1+"))
}
