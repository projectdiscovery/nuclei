package config

import (
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
)

// IgnoreFile is an internal nuclei template blocking configuration file
type IgnoreFile struct {
	Tags  []string `yaml:"tags"`
	Files []string `yaml:"files"`
}

// ReadIgnoreFile reads the active .nuclei-ignore file and returns blocked tags
// and paths. Callers must decide whether a read error is recoverable. Malformed
// content is returned as an error to prevent a fail-open scan.
func ReadIgnoreFile() (IgnoreFile, error) {
	path := DefaultConfig.GetActiveIgnoreFilePath()

	file, err := os.Open(path)
	if err != nil {
		return IgnoreFile{}, fmt.Errorf("error opening %q: %w", path, err)
	}
	defer func() {
		_ = file.Close()
	}()

	decoder := yaml.NewDecoder(file)
	ignore := IgnoreFile{}
	if err := decoder.Decode(&ignore); err != nil {
		return IgnoreFile{}, fmt.Errorf("error parsing %q: %w", path, err)
	}

	var additionalDocument any
	if err := decoder.Decode(&additionalDocument); !errors.Is(err, io.EOF) {
		if err != nil {
			return IgnoreFile{}, fmt.Errorf("error parsing %q: %w", path, err)
		}

		return IgnoreFile{}, fmt.Errorf("error parsing %q: multiple YAML documents are not supported", path)
	}

	return ignore, nil
}

// WriteActiveIgnoreFile atomically replaces the active root ignore file.
func (c *Config) WriteActiveIgnoreFile(data []byte) error {
	if err := atomicWriteFile(c.GetActiveIgnoreFilePath(), data, 0o600); err != nil {
		return fmt.Errorf("write active .nuclei-ignore file: %w", err)
	}

	return nil
}

// IgnoreFileNeedsUpdate reports whether the active ignore file is
// missing or differs from the latest known hash.
func (c *Config) IgnoreFileNeedsUpdate(latestHash string) bool {
	ignoreFilePath := c.GetActiveIgnoreFilePath()

	contents, err := os.ReadFile(ignoreFilePath)
	if err != nil {
		return true
	}
	if latestHash == "" {
		return false
	}

	return ignoreFileHash(contents) != latestHash
}

// NeedsIgnoreFileUpdate reports whether the active ignore file differs
// from the deprecated in-memory remote hash.
//
// Deprecated: pass the transient remote hash to IgnoreFileNeedsUpdate.
func (c *Config) NeedsIgnoreFileUpdate() bool {
	c.m.Lock()
	latestHash := c.LatestNucleiIgnoreHash
	c.m.Unlock()

	return c.IgnoreFileNeedsUpdate(latestHash)
}

// UpdateNucleiIgnoreHash refreshes the deprecated in-memory compatibility
// field from the active ignore file.
//
// Deprecated: local ignore-file hashes are derived from the active file.
func (c *Config) UpdateNucleiIgnoreHash() error {
	ignoreFilePath := c.GetActiveIgnoreFilePath()
	contents, err := os.ReadFile(ignoreFilePath)
	if err != nil {
		return fmt.Errorf("read active .nuclei-ignore file %q: %w", ignoreFilePath, err)
	}

	c.NucleiIgnoreHash = ignoreFileHash(contents)
	return nil
}

func ignoreFileHash(contents []byte) string {
	return fmt.Sprintf("%x", md5.Sum(contents))
}
