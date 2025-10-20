package openapi

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
)

// OpenAPIDownloader implements the SpecDownloader interface for OpenAPI 3.0 specs
type OpenAPIDownloader struct{}

// NewDownloader creates a new OpenAPI downloader
func NewDownloader() formats.SpecDownloader {
	return &OpenAPIDownloader{}
}

// This function downloads an OpenAPI 3.0 spec from the given URL and saves it to tmpDir
func (d *OpenAPIDownloader) Download(urlStr, tmpDir string) (string, error) {
	// Validate URL format, OpenAPI 3.0 specs are typically JSON
	if !strings.HasSuffix(urlStr, ".json") && !strings.Contains(urlStr, "openapi") {
		return "", fmt.Errorf("URL does not appear to be an OpenAPI JSON spec")
	}

	var httpTimeout = 30 * time.Second
	const maxSpecSizeBytes = 10 * 1024 * 1024 // 10MB
	client := &http.Client{Timeout: httpTimeout}

	resp, err := client.Get(urlStr)
	if err != nil {
		return "", errors.Wrap(err, "failed to download OpenAPI spec")
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d when downloading OpenAPI spec", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxSpecSizeBytes))
	if err != nil {
		return "", errors.Wrap(err, "failed to read response body")
	}

	// Validate it's a valid JSON and has OpenAPI structure
	var spec map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &spec); err != nil {
		return "", fmt.Errorf("downloaded content is not valid JSON: %w", err)
	}

	// Check if it's an OpenAPI 3.0 spec
	if openapi, exists := spec["openapi"]; exists {
		if openapiStr, ok := openapi.(string); ok && strings.HasPrefix(openapiStr, "3.") {
			// Valid OpenAPI 3.0 spec
		} else {
			return "", fmt.Errorf("not a valid OpenAPI 3.0 spec (found version: %v)", openapi)
		}
	} else {
		return "", fmt.Errorf("not an OpenAPI spec (missing 'openapi' field)")
	}

	// Extract host from URL for server configuration
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", errors.Wrap(err, "failed to parse URL")
	}
	host := parsedURL.Host
	scheme := parsedURL.Scheme
	if scheme == "" {
		scheme = "https"
	}

	// Add servers section if missing or empty
	servers, exists := spec["servers"]
	if !exists || servers == nil {
		spec["servers"] = []map[string]interface{}{{"url": scheme + "://" + host}}
	} else if serverList, ok := servers.([]interface{}); ok && len(serverList) == 0 {
		spec["servers"] = []map[string]interface{}{{"url": scheme + "://" + host}}
	}

	// Marshal back to JSON
	modifiedJSON, err := json.Marshal(spec)
	if err != nil {
		return "", errors.Wrap(err, "failed to marshal modified spec")
	}

	// Create output directory
	openapiDir := filepath.Join(tmpDir, "openapi")
	if err := os.MkdirAll(openapiDir, 0755); err != nil {
		return "", errors.Wrap(err, "failed to create openapi directory")
	}

	// Generate filename
	filename := fmt.Sprintf("openapi-spec-%d.json", time.Now().Unix())
	filePath := filepath.Join(openapiDir, filename)

	// Write file
	file, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}

	defer func() {
		_ = file.Close()
	}()

	if _, writeErr := file.Write(modifiedJSON); writeErr != nil {
		_ = os.Remove(filePath)
		return "", errors.Wrap(writeErr, "failed to write OpenAPI spec to file")
	}

	return filePath, nil
}

// SupportedExtensions returns the list of supported file extensions for OpenAPI
func (d *OpenAPIDownloader) SupportedExtensions() []string {
	return []string{".json"}
}
