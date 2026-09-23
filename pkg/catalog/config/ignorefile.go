package config

import (
	"bytes"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
)

// maxIgnoreFileBytes caps untrusted ignore-file payloads (PDTM downloads,
// template archives) before YAML decode.
const maxIgnoreFileBytes = 1 << 20

var errMultipleIgnoreFileDocuments = errors.New("multiple YAML documents are not supported")

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

	ignore, err := decodeIgnoreFile(file, false)
	if err != nil {
		return IgnoreFile{}, fmt.Errorf("error parsing %q: %w", path, err)
	}

	return ignore, nil
}

// WriteActiveIgnoreFile atomically replaces the active root ignore file.
func (c *Config) WriteActiveIgnoreFile(data []byte) error {
	path := c.GetActiveIgnoreFilePath()
	if err := validateIgnoreFileContents(data); err != nil {
		return fmt.Errorf("invalid active .nuclei-ignore file %q: %w", path, err)
	}

	if err := atomicWriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write active .nuclei-ignore file: %w", err)
	}

	return nil
}

func validateIgnoreFileContents(data []byte) error {
	if len(data) > maxIgnoreFileBytes {
		return fmt.Errorf("payload exceeds %d bytes", maxIgnoreFileBytes)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return errors.New("empty document")
	}

	if _, err := decodeIgnoreFile(bytes.NewReader(data), true); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("empty document")
		}
		return err
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var raw map[string]any
	if err := decoder.Decode(&raw); err != nil {
		return err
	}
	if raw == nil {
		return errors.New("document must be a YAML mapping")
	}

	allowed := ignoreFileFieldNames()
	found := false
	for key := range raw {
		if !slices.Contains(allowed, key) {
			return fmt.Errorf("unknown field %q", key)
		}
		found = true
	}
	if !found {
		return fmt.Errorf("document must define at least one of %s", strings.Join(allowed, ", "))
	}

	return nil
}

func decodeIgnoreFile(r io.Reader, knownFields bool) (IgnoreFile, error) {
	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(knownFields)

	ignore := IgnoreFile{}
	if err := decoder.Decode(&ignore); err != nil {
		return IgnoreFile{}, err
	}

	var additionalDocument any
	if err := decoder.Decode(&additionalDocument); !errors.Is(err, io.EOF) {
		if err != nil {
			return IgnoreFile{}, err
		}

		return IgnoreFile{}, errMultipleIgnoreFileDocuments
	}

	return ignore, nil
}

func ignoreFileFieldNames() []string {
	typ := reflect.TypeOf(IgnoreFile{})
	names := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		name, _, _ := strings.Cut(typ.Field(i).Tag.Get("yaml"), ",")
		if name == "" || name == "-" {
			continue
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return names
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
