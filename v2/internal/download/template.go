package download

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	fileutil "github.com/projectdiscovery/utils/file"
)

const (
	checkSumFilePerm = 0644
)

// TemplateManager is a manager for templates.
// It downloads / updates / installs templates.
type TemplateManager struct {
	config *config.Config
}

// NewTemplateManager creates a new TemplateManager.
func NewTemplateManager(cfg *config.Config) *TemplateManager {
	return &TemplateManager{config: cfg}
}

// FreshInstallIfNotExists installs templates if they are not already installed
// if templates directory already exists, it does nothing
func (t *TemplateManager) FreshInstallIfNotExists() error {
	if t.config.TemplateVersion != "" || fileutil.FolderExists(t.config.TemplatesDirectory) {
		return nil
	}
	gologger.Info().Msgf("nuclei-templates are not installed, installing...")
	return nil
}

// installTemplatesAt installs templates at given directory
func (t *TemplateManager) installTemplatesAt(dir string) error {

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
