package swagger

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	"gopkg.in/yaml.v3"
)

// SwaggerDownloader implements the SpecDownloader interface for Swagger 2.0 specs
type SwaggerDownloader struct{}

// NewDownloader creates a new Swagger downloader
func NewDownloader() formats.SpecDownloader {
	return &SwaggerDownloader{}
}

// This function downloads a Swagger 2.0 spec from the given URL and saves it to tmpDir
func (d *SwaggerDownloader) Download(urlStr, tmpDir string) (string, error) {
	// Swagger can be JSON or YAML
	supportedExts := []string{".json", ".yaml", ".yml"}
	isSupported := false
	for _, ext := range supportedExts {
		if strings.HasSuffix(urlStr, ext) {
			isSupported = true
			break
		}
	}
	if !isSupported && !strings.Contains(urlStr, "swagger") {
		return "", fmt.Errorf("URL does not appear to be a Swagger spec (supported: %v)", supportedExts)
	}

	var httpTimeout = 30 * time.Second
	const maxSpecSizeBytes = 10 * 1024 * 1024 // 10MB
	client := &http.Client{Timeout: httpTimeout}

	resp, err := client.Get(urlStr)
	if err != nil {
		return "", errors.Wrap(err, "failed to download Swagger spec")
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d when downloading Swagger spec", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxSpecSizeBytes))
	if err != nil {
		return "", errors.Wrap(err, "failed to read response body")
	}

	// Determine format and parse
	var spec map[string]interface{}
	var isYAML bool

	// Try JSON first
	if err := json.Unmarshal(bodyBytes, &spec); err != nil {
		// Then try YAML
		if err := yaml.Unmarshal(bodyBytes, &spec); err != nil {
			return "", fmt.Errorf("downloaded content is neither valid JSON nor YAML: %w", err)
		}
		isYAML = true
	}

	// Validate it's a Swagger 2.0 spec
	if swagger, exists := spec["swagger"]; exists {
		if swaggerStr, ok := swagger.(string); ok && strings.HasPrefix(swaggerStr, "2.") {
			// Valid Swagger 2.0 spec
		} else {
			return "", fmt.Errorf("not a valid Swagger 2.0 spec (found version: %v)", swagger)
		}
	} else {
		return "", fmt.Errorf("not a Swagger spec (missing 'swagger' field)")
	}

	// Extract host from URL for host configuration
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", errors.Wrap(err, "failed to parse URL")
	}
	host := parsedURL.Host

	// Add host if missing
	if _, exists := spec["host"]; !exists {
		spec["host"] = host
	}

	// Add schemes if missing
	if _, exists := spec["schemes"]; !exists {
		scheme := parsedURL.Scheme
		if scheme == "" {
			scheme = "https"
		}
		spec["schemes"] = []string{scheme}
	}

	// Create output directory
	swaggerDir := filepath.Join(tmpDir, "swagger")
	if err := os.MkdirAll(swaggerDir, 0755); err != nil {
		return "", errors.Wrap(err, "failed to create swagger directory")
	}

	// Generate filename and content based on original format
	var filename string
	var content []byte

	if isYAML {
		filename = fmt.Sprintf("swagger-spec-%d.yaml", time.Now().Unix())
		content, err = yaml.Marshal(spec)
		if err != nil {
			return "", errors.Wrap(err, "failed to marshal modified YAML spec")
		}
	} else {
		filename = fmt.Sprintf("swagger-spec-%d.json", time.Now().Unix())
		content, err = json.Marshal(spec)
		if err != nil {
			return "", errors.Wrap(err, "failed to marshal modified JSON spec")
		}
	}

	filePath := filepath.Join(swaggerDir, filename)

	// Write file
	file, err := os.Create(filePath)
	if err != nil {
		return "", errors.Wrap(err, "failed to create file")
	}

	defer func() {
		_ = file.Close()
	}()

	if _, writeErr := file.Write(content); writeErr != nil {
		_ = os.Remove(filePath)
		return "", errors.Wrap(writeErr, "failed to write file")
	}

	return filePath, nil
}

// SupportedExtensions returns the list of supported file extensions for Swagger
func (d *SwaggerDownloader) SupportedExtensions() []string {
	return []string{".json", ".yaml", ".yml"}
}
