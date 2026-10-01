package openapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/retryablehttp-go"
)

func TestOpenAPIDownloader_SupportedExtensions(t *testing.T) {
	downloader := &OpenAPIDownloader{}
	extensions := downloader.SupportedExtensions()

	expected := []string{".json"}
	if len(extensions) != len(expected) {
		t.Errorf("Expected %d extensions, got %d", len(expected), len(extensions))
	}

	for i, ext := range extensions {
		if ext != expected[i] {
			t.Errorf("Expected extension %s, got %s", expected[i], ext)
		}
	}
}

func TestOpenAPIDownloader_Download_Success(t *testing.T) {
	// Create a mock OpenAPI spec
	mockSpec := map[string]interface{}{
		"openapi": "3.0.0",
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
	tmpDir, err := os.MkdirTemp("", "openapi_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Fatalf("Failed to remove temp dir: %v", err)
		}
	}()

	// Test download
	downloader := &OpenAPIDownloader{}
	filePath, err := downloader.Download(server.URL+"/openapi.json", tmpDir, nil)
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

	// Verify servers field was added
	servers, exists := downloadedSpec["servers"]
	if !exists {
		t.Error("Servers field was not added to the spec")
	}

	if serversList, ok := servers.([]interface{}); ok {
		if len(serversList) == 0 {
			t.Error("Servers list is empty")
		}
	} else {
		t.Error("Servers field is not a list")
	}
}

func TestOpenAPIDownloader_Download_NonJSONURL(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "openapi_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Fatalf("Failed to remove temp dir: %v", err)
		}
	}()

	downloader := &OpenAPIDownloader{}
	_, err = downloader.Download("http://example.com/spec.yaml", tmpDir, nil)
	if err == nil {
		t.Error("Expected error for non-JSON URL, but got none")
	}

	if !strings.Contains(err.Error(), "URL does not appear to be an OpenAPI JSON spec") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestOpenAPIDownloader_Download_HTTPError(t *testing.T) {
	// Create mock server that returns 404
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tmpDir, err := os.MkdirTemp("", "openapi_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Fatalf("Failed to remove temp dir: %v", err)
		}
	}()

	downloader := &OpenAPIDownloader{}
	_, err = downloader.Download(server.URL+"/openapi.json", tmpDir, nil)
	if err == nil {
		t.Error("Expected error for HTTP 404, but got none")
	}
}

func TestOpenAPIDownloader_Download_InvalidJSON(t *testing.T) {
	// Create mock server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte("invalid json")); err != nil {
			http.Error(w, "failed to write response", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	tmpDir, err := os.MkdirTemp("", "openapi_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Fatalf("Failed to remove temp dir: %v", err)
		}
	}()

	downloader := &OpenAPIDownloader{}
	_, err = downloader.Download(server.URL+"/openapi.json", tmpDir, nil)
	if err == nil {
		t.Error("Expected error for invalid JSON, but got none")
	}
}

func TestOpenAPIDownloader_Download_Timeout(t *testing.T) {
	// Create mock server with delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Outlasts the client timeout below. Waiting out the real 30s default
		// cost this test 35s, which was a seventh of the whole unit suite.
		time.Sleep(500 * time.Millisecond)
		if err := json.NewEncoder(w).Encode(map[string]interface{}{"test": "data"}); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	tmpDir, err := os.MkdirTemp("", "openapi_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Fatalf("Failed to remove temp dir: %v", err)
		}
	}()

	downloader := &OpenAPIDownloader{}
	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	client.HTTPClient.Timeout = 100 * time.Millisecond
	_, err = downloader.Download(server.URL+"/openapi.json", tmpDir, client)
	if err == nil {
		t.Fatal("Expected timeout error, but got none")
	}
	// Assert it timed out rather than merely erroring: the spec this server
	// returns is invalid, so a test that only checks for any error passes even
	// when the timeout never fires.
	if !os.IsTimeout(err) && !strings.Contains(err.Error(), "Timeout") {
		t.Fatalf("Expected a timeout error, got: %v", err)
	}
}

func TestOpenAPIDownloader_Download_WithExistingServers(t *testing.T) {
	// Create a mock OpenAPI spec with existing servers
	mockSpec := map[string]interface{}{
		"openapi": "3.0.0",
		"info": map[string]interface{}{
			"title":   "Test API",
			"version": "1.0.0",
		},
		"servers": []interface{}{
			map[string]interface{}{
				"url": "https://existing-server.com",
			},
		},
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

	tmpDir, err := os.MkdirTemp("", "openapi_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Fatalf("Failed to remove temp dir: %v", err)
		}
	}()

	downloader := &OpenAPIDownloader{}
	filePath, err := downloader.Download(server.URL+"/openapi.json", tmpDir, nil)
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}

	// Verify existing servers are preserved
	content, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read downloaded file: %v", err)
	}

	var downloadedSpec map[string]interface{}
	if err := json.Unmarshal(content, &downloadedSpec); err != nil {
		t.Fatalf("Failed to parse downloaded JSON: %v", err)
	}

	servers, exists := downloadedSpec["servers"]
	if !exists {
		t.Error("Servers field was removed from the spec")
	}

	if serversList, ok := servers.([]interface{}); ok {
		if len(serversList) != 1 {
			t.Errorf("Expected 1 server, got %d", len(serversList))
		}
	}
}

// Helper function to check if file exists
func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}
