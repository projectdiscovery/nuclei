package installer

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	stringsutil "github.com/projectdiscovery/utils/strings"
	updateutils "github.com/projectdiscovery/utils/update"
)

const (
	checkSumFilePerm = 0644
)

var (
	HideProgressBar  = false
	HideReleaseNotes = false
)

// TemplateManager is a manager for templates.
// It downloads / updates / installs templates.
type TemplateManager struct{}

// FreshInstallIfNotExists installs templates if they are not already installed
// if templates directory already exists, it does nothing
func (t *TemplateManager) FreshInstallIfNotExists() error {
	if fileutil.FolderExists(config.DefaultConfig.TemplatesDirectory) {
		return nil
	}
	gologger.Info().Msgf("nuclei-templates are not installed, installing...")
	return t.installTemplatesAt(config.DefaultConfig.TemplatesDirectory)
}

// installTemplatesAt installs templates at given directory
func (t *TemplateManager) installTemplatesAt(dir string) error {
	if !fileutil.FolderExists(dir) {
		if err := fileutil.CreateFolder(dir); err != nil {
			return errorutil.NewWithErr(err).Msgf("failed to create directory at %s", dir)
		}
	}
	ghrd, err := updateutils.NewghReleaseDownloader(config.OfficialNucleiTeamplatesRepoName)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("failed to install templates at %s", dir)
	}

	callbackFunc := func(uri string, f fs.FileInfo, r io.Reader) error {
		writePath := t.getAbsoluteFilePath(dir, uri, f)
		if writePath == "" {
			// skip writing file
			return nil
		}
		bin, err := io.ReadAll(r)
		if err != nil {
			// if error occurs, iteration also stops
			return errorutil.NewWithErr(err).Msgf("failed to read file %s", uri)
		}
		os.WriteFile(writePath, bin, f.Mode())
		return nil
	}
	err = ghrd.DownloadSourceWithCallback(!HideProgressBar, callbackFunc)
	if err != nil {
		return err
	}
	// after installation create and write checksums to .checksum file
	return t.writeChecksumFileInDir(dir)
}

// getAbsoluteFilePath returns absolute path where a file should be written based on given uri(i.e files in zip)
// if returned path is empty, it means that file should not be written and skipped
func (t *TemplateManager) getAbsoluteFilePath(templatedir, uri string, f fs.FileInfo) string {
	// overwrite .nuclei-ignore everytime nuclei-templates are downloaded
	if f.Name() == config.NucleiIgnoreFileName {
		return config.DefaultConfig.GetIgnoreFilePath()
	}
	// skip all meta files
	if !strings.EqualFold(f.Name(), config.NewTemplateAdditionsFileName) {
		if strings.TrimSpace(f.Name()) == "" || strings.HasPrefix(f.Name(), ".") || strings.EqualFold(f.Name(), "README.md") {
			return ""
		}
	}

	// get root or leftmost directory name from path
	// this is in format `projectdiscovery-nuclei-templates-commithash`

	index := strings.Index(uri, "/")
	if index == -1 {
		// zip files does not have directory at all , in this case log error but continue
		gologger.Warning().Msgf("failed to get directory name from uri: %s", uri)
		return filepath.Join(templatedir, uri)
	}
	// seperator is also included in rootDir
	rootDirectory := uri[:index+1]
	relPath := strings.TrimPrefix(uri, rootDirectory)

	// if it is a github meta directory skip it
	if stringsutil.HasPrefixAny(relPath, ".github", ".git") {
		return ""
	}

	newPath := filepath.Clean(filepath.Join(templatedir, relPath))

	if !strings.HasPrefix(newPath, templatedir) {
		// we don't allow LFI
		return ""
	}

	if relPath != "" && f.IsDir() {
		// if uri is a directory, create it
		if err := fileutil.CreateFolder(newPath); err != nil {
			gologger.Warning().Msgf("uri %v: got %s while installing templates", uri, err)
		}
		return ""
	}
	return newPath
}

// writeChecksumFileInDir creates checksums of all yaml files in given directory
// and writes them to a file named .checksum
func (t *TemplateManager) writeChecksumFileInDir(dir string) error {
	checksumMap, err := t.getChecksumMap(dir)
	if err != nil {
		return err
	}
	checksumFilePath := filepath.Join(dir, ".checksum")
	var buff bytes.Buffer
	for k, v := range checksumMap {
		buff.WriteString(k + "," + v)
	}
	return os.WriteFile(checksumFilePath, buff.Bytes(), checkSumFilePerm)
}

// getChecksumMap returns a map containing checksums (md5 hash) of all yaml files (with .yaml extension)
func (t *TemplateManager) getChecksumMap(dir string) (map[string]string, error) {
	// getchecksumMap walks given directory `dir` and returns a map containing
	// checksums (md5 hash) of all yaml files (with .yaml extension) and the
	// format is map[filePath]checksum
	checksumMap := map[string]string{}

	getChecksum := func(filepath string) (string, error) {
		// return md5 hash of the file
		bin, err := os.ReadFile(filepath)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%x", md5.Sum(bin)), nil
	}

	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && filepath.Ext(path) == ".yaml" {
			checksum, err := getChecksum(path)
			if err != nil {
				return err
			}
			checksumMap[path] = checksum
		}
		return nil
	})
	return checksumMap, nil
}
