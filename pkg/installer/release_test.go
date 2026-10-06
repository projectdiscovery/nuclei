package installer

import (
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"time"

	updateutils "github.com/projectdiscovery/utils/update"
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
