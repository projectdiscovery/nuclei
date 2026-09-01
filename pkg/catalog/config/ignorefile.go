package config

import (
	"crypto/md5"
	"fmt"
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
)

// IgnoreFile is an internal nuclei template blocking configuration file
type IgnoreFile struct {
	Tags  []string `yaml:"tags"`
	Files []string `yaml:"files"`
}

// ReadIgnoreFile reads the .nuclei-ignore file returning blocked tags and paths.
func ReadIgnoreFile() IgnoreFile {
	path := DefaultConfig.GetActiveIgnoreFilePath()
	file, err := os.Open(path)
	if err != nil {
		gologger.Error().Msgf("Could not read .nuclei-ignore file %q: %s\n", path, err)
		return IgnoreFile{}
	}
	defer func() {
		_ = file.Close()
	}()

	ignore := IgnoreFile{}
	if err := yaml.NewDecoder(file).Decode(&ignore); err != nil {
		gologger.Error().Msgf("Could not parse .nuclei-ignore file %q: %s\n", path, err)
		return IgnoreFile{}
	}

	return ignore
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
