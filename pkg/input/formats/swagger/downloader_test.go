package swagger

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestSwaggerDownloader_SupportedExtensions(t *testing.T) {
	downloader := &SwaggerDownloader{}
	extensions := downloader.SupportedExtensions()

	expected := []string{".json", ".yaml", ".yml"}
	if len(extensions) != len(expected) {
		t.Errorf("Expected %d extensions, got %d", len(expected), len(extensions))
	}

	for i, ext := range extensions {
		if ext != expected[i] {
			t.Errorf("Expected extension %s, got %s", expected[i], ext)
		}
	}
}

func TestSwaggerDownloader_Download_JSON_Success(t *testing.T) {
	// Create a mock Swagger spec (JSON)
	mockSpec := map[string]interface{}{
		"swagger": "2.0",
		"info": map[string]interface{}{
			"title":   "Test API",
			"version": "1.0.0",
		},
		"paths": map[string]interface{}{
			"/test": map[string]interface{}{
				"get": map[string]interface{}{
					"summary": "Test endpoint",
				},
			},
		},
	}

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(mockSpec); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "swagger_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Fatalf("Failed to remove temp dir: %v", err)
		}
	}()

	// Test download
	downloader := &SwaggerDownloader{}
	filePath, err := downloader.Download(server.URL+"/swagger.json", tmpDir, nil)
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}

	// Verify file exists
	if !fileExists(filePath) {
		t.Errorf("Downloaded file does not exist: %s", filePath)
	}

	// Verify file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read downloaded file: %v", err)
	}

	var downloadedSpec map[string]interface{}
	if err := json.Unmarshal(content, &downloadedSpec); err != nil {
		t.Fatalf("Failed to parse downloaded JSON: %v", err)
	}

	// Verify host field was added
	_, exists := downloadedSpec["host"]
	if !exists {
		t.Error("Host field was not added to the spec")
	}
}

func TestSwaggerDownloader_Download_YAML_Success(t *testing.T) {
	// Create a mock Swagger spec (YAML)
	mockSpecYAML := `
swagger: "2.0"
info:
  title: "Test API"
  version: "1.0.0"
paths:
  /test:
    get:
      summary: "Test endpoint"
`

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		if _, err := w.Write([]byte(mockSpecYAML)); err != nil {
			http.Error(w, "failed to write response", http.StatusInternalServerError)
		}
	}))

	defer server.Close()

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "swagger_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Fatalf("Failed to remove temp dir: %v", err)
		}
	}()

	// Test download
	downloader := &SwaggerDownloader{}
	filePath, err := downloader.Download(server.URL+"/swagger.yaml", tmpDir, nil)
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}

	// Verify file exists
	if !fileExists(filePath) {
		t.Errorf("Downloaded file does not exist: %s", filePath)
	}

	// Verify file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read downloaded file: %v", err)
	}

	var downloadedSpec map[string]interface{}
	if err := yaml.Unmarshal(content, &downloadedSpec); err != nil {
		t.Fatalf("Failed to parse downloaded YAML: %v", err)
	}

	// Verify host field was added
	_, exists := downloadedSpec["host"]
	if !exists {
		t.Error("Host field was not added to the spec")
	}
}

func TestSwaggerDownloader_Download_UnsupportedExtension(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "swagger_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Fatalf("Failed to remove temp dir: %v", err)
		}
	}()

	downloader := &SwaggerDownloader{}
	_, err = downloader.Download("http://example.com/spec.xml", tmpDir, nil)
	if err == nil {
		t.Error("Expected error for unsupported extension, but got none")
	}

	if !strings.Contains(err.Error(), "URL does not appear to be a Swagger spec") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestSwaggerDownloader_Download_HTTPError(t *testing.T) {
	// Create mock server that returns 404
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tmpDir, err := os.MkdirTemp("", "swagger_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Fatalf("Failed to remove temp dir: %v", err)
		}
	}()

	downloader := &SwaggerDownloader{}
	_, err = downloader.Download(server.URL+"/swagger.json", tmpDir, nil)
	if err == nil {
		t.Error("Expected error for HTTP 404, but got none")
	}
}

func TestSwaggerDownloader_Download_InvalidJSON(t *testing.T) {
	// Create mock server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte("invalid json")); err != nil {
			http.Error(w, "failed to write response", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	tmpDir, err := os.MkdirTemp("", "swagger_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Fatalf("Failed to remove temp dir: %v", err)
		}
	}()

	downloader := &SwaggerDownloader{}
	_, err = downloader.Download(server.URL+"/swagger.json", tmpDir, nil)
	if err == nil {
		t.Error("Expected error for invalid JSON, but got none")
	}
}

func TestSwaggerDownloader_Download_InvalidYAML(t *testing.T) {
	// Create mock server that returns invalid YAML
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		if _, err := w.Write([]byte("invalid: yaml: content: [")); err != nil {
			http.Error(w, "failed to write response", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	tmpDir, err := os.MkdirTemp("", "swagger_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Fatalf("Failed to remove temp dir: %v", err)
		}
	}()

	downloader := &SwaggerDownloader{}
	_, err = downloader.Download(server.URL+"/swagger.yaml", tmpDir, nil)
	if err == nil {
		t.Error("Expected error for invalid YAML, but got none")
	}
}

func TestSwaggerDownloader_Download_Timeout(t *testing.T) {
	// Create mock server with delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(35 * time.Second) // Longer than 30 second timeout
		if err := json.NewEncoder(w).Encode(map[string]interface{}{"test": "data"}); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	tmpDir, err := os.MkdirTemp("", "swagger_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Fatalf("Failed to remove temp dir: %v", err)
		}
	}()

	downloader := &SwaggerDownloader{}
	_, err = downloader.Download(server.URL+"/swagger.json", tmpDir, nil)
	if err == nil {
		t.Error("Expected timeout error, but got none")
	}
}

func TestSwaggerDownloader_Download_WithExistingHost(t *testing.T) {
	// Create a mock Swagger spec with existing host
	mockSpec := map[string]interface{}{
		"swagger": "2.0",
		"info": map[string]interface{}{
			"title":   "Test API",
			"version": "1.0.0",
		},
		"host":  "existing-host.com",
		"paths": map[string]interface{}{},
	}

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(mockSpec); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	tmpDir, err := os.MkdirTemp("", "swagger_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Fatalf("Failed to remove temp dir: %v", err)
		}
	}()

	downloader := &SwaggerDownloader{}
	filePath, err := downloader.Download(server.URL+"/swagger.json", tmpDir, nil)
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}

	// Verify existing host is preserved
	content, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read downloaded file: %v", err)
	}

	var downloadedSpec map[string]interface{}
	if err := json.Unmarshal(content, &downloadedSpec); err != nil {
		t.Fatalf("Failed to parse downloaded JSON: %v", err)
	}

	host, exists := downloadedSpec["host"]
	if !exists {
		t.Error("Host field was removed from the spec")
	}

	if hostStr, ok := host.(string); !ok || hostStr != "existing-host.com" {
		t.Errorf("Expected host 'existing-host.com', got '%v'", host)
	}
}

// Helper function to check if file exists
func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}
