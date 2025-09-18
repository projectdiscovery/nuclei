package dataformat

import (
	"testing"

	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultiPartFormEncode(t *testing.T) {
	tests := []struct {
		name     string
		fields   map[string]any
		wantErr  bool
		expected map[string]any
	}{
		{
			name: "duplicate fields ([]string) - checkbox scenario",
			fields: map[string]any{
				"interests": []string{"sports", "music", "reading"},
				"colors":    []string{"red", "blue"},
			},
			expected: map[string]any{
				"interests": []string{"sports", "music", "reading"},
				"colors":    []string{"red", "blue"},
			},
		},
		{
			name: "single string fields - backward compatibility",
			fields: map[string]any{
				"username": "john",
				"email":    "john@example.com",
			},
			expected: map[string]any{
				"username": "john",
				"email":    "john@example.com",
			},
		},
		{
			name: "mixed types",
			fields: map[string]any{
				"string":     "text",
				"array":      []string{"item1", "item2"},
				"number":     42,                            // tests fmt.Sprint fallback
				"float":      3.14,                          // tests float conversion
				"boolean":    true,                          // tests boolean conversion
				"zero":       0,                             // tests zero value
				"emptyStr":   "",                            // tests empty string
				"negative":   -123,                          // tests negative number
				"nil":        nil,                           // tests nil value
				"mixedArray": []any{"str", 123, false, nil}, // tests mixed type array
			},
			expected: map[string]any{
				"string":     "text",
				"array":      []string{"item1", "item2"},
				"number":     "42",                                // numbers are converted to strings in multipart
				"float":      "3.14",                              // floats are converted to strings
				"boolean":    "true",                              // booleans are converted to strings
				"zero":       "0",                                 // zero value converted to string
				"emptyStr":   "",                                  // empty string remains empty
				"negative":   "-123",                              // negative numbers converted to strings
				"nil":        "",                                  // nil values converted to "" string
				"mixedArray": []string{"str", "123", "false", ""}, // mixed array converted to string array
			},
		},
		{
			name: "empty array - should not appear in output",
			fields: map[string]any{
				"emptyArray":  []string{},
				"normalField": "value",
			},
			expected: map[string]any{
				"normalField": "value",
				// emptyArray should not appear in decoded output
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Test panicked: %v", r)
				}
			}()

			form := NewMultiPartForm()
			form.boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"

			kv := mapsutil.NewOrderedMap[string, any]()
			for k, v := range tt.fields {
				kv.Set(k, v)
			}

			encoded, err := form.Encode(KVOrderedMap(&kv))

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			// Decode the encoded multipart data
			decoded, err := form.Decode(encoded)
			require.NoError(t, err)

			// Compare decoded values with expected values
			for expectedKey, expectedValue := range tt.expected {
				actualValue := decoded.Get(expectedKey)
				switch expected := expectedValue.(type) {
				case []string:
					actual, ok := actualValue.([]string)
					require.True(t, ok, "Expected []string for key %s, got %T", expectedKey, actualValue)
					assert.ElementsMatch(t, expected, actual, "Values mismatch for key %s", expectedKey)
				case []any:
					actual, ok := actualValue.([]any)
					require.True(t, ok, "Expected []any for key %s, got %T", expectedKey, actualValue)
					assert.ElementsMatch(t, expected, actual, "Values mismatch for key %s", expectedKey)
				case string:
					actual, ok := actualValue.(string)
					require.True(t, ok, "Expected string for key %s, got %T", expectedKey, actualValue)
					assert.Equal(t, expected, actual, "Values mismatch for key %s", expectedKey)
				default:
					assert.Equal(t, expected, actualValue, "Values mismatch for key %s", expectedKey)
				}
			}

			// Ensure no unexpected keys are present in decoded output
			decoded.Iterate(func(key string, value any) bool {
				_, exists := tt.expected[key]
				assert.True(t, exists, "Unexpected key %s found in decoded output", key)
				return true
			})

			t.Logf("Encoded output:\n%s", encoded)
		})
	}
}

func TestMultiPartFormRoundTrip(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Test panicked: %v", r)
		}
	}()

	form := NewMultiPartForm()
	form.boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"

	original := mapsutil.NewOrderedMap[string, any]()
	original.Set("username", "john")
	original.Set("interests", []string{"sports", "music", "reading"})

	encoded, err := form.Encode(KVOrderedMap(&original))
	require.NoError(t, err)

	decoded, err := form.Decode(encoded)
	require.NoError(t, err)

	assert.Equal(t, "john", decoded.Get("username"))
	assert.ElementsMatch(t, []string{"sports", "music", "reading"}, decoded.Get("interests"))

	t.Logf("Encoded output:\n%s", encoded)
}

func TestMultiPartFormFileUpload(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Test panicked: %v", r)
		}
	}()

	// Test decoding of a manually crafted multipart form with files
	form := NewMultiPartForm()
	form.boundary = "----WebKitFormBoundaryFileUploadTest"

	// Manually craft a multipart form with file uploads
	multipartData := `------WebKitFormBoundaryFileUploadTest
Content-Disposition: form-data; name="name"

John Doe
------WebKitFormBoundaryFileUploadTest
Content-Disposition: form-data; name="email"

john@example.com
------WebKitFormBoundaryFileUploadTest
Content-Disposition: form-data; name="profile_picture"; filename="profile.jpg"
Content-Type: image/jpeg

fake_jpeg_binary_data_here
------WebKitFormBoundaryFileUploadTest
Content-Disposition: form-data; name="documents"; filename="resume.pdf"
Content-Type: application/pdf

fake_pdf_content_1
------WebKitFormBoundaryFileUploadTest
Content-Disposition: form-data; name="documents"; filename="cover_letter.pdf"
Content-Type: application/pdf

fake_pdf_content_2
------WebKitFormBoundaryFileUploadTest
Content-Disposition: form-data; name="skills"

Go
------WebKitFormBoundaryFileUploadTest
Content-Disposition: form-data; name="skills"

JavaScript
------WebKitFormBoundaryFileUploadTest
Content-Disposition: form-data; name="skills"

Python
------WebKitFormBoundaryFileUploadTest--
`

	// Test decoding
	decoded, err := form.Decode(multipartData)
	require.NoError(t, err)

	// Verify regular fields
	assert.Equal(t, "John Doe", decoded.Get("name"))
	assert.Equal(t, "john@example.com", decoded.Get("email"))
	assert.Equal(t, []string{"Go", "JavaScript", "Python"}, decoded.Get("skills"))

	// Verify file fields
	profilePicture := decoded.Get("profile_picture")
	require.NotNil(t, profilePicture)
	profileArray, ok := profilePicture.([]interface{})
	require.True(t, ok, "Expected []interface{} for profile_picture")
	require.Len(t, profileArray, 1)
	assert.Equal(t, "fake_jpeg_binary_data_here", profileArray[0])

	documents := decoded.Get("documents")
	require.NotNil(t, documents)
	documentsArray, ok := documents.([]interface{})
	require.True(t, ok, "Expected []interface{} for documents")
	require.Len(t, documentsArray, 2)
	assert.Contains(t, documentsArray, "fake_pdf_content_1")
	assert.Contains(t, documentsArray, "fake_pdf_content_2")
}

func TestMultiPartForm_SetGetFileMetadata(t *testing.T) {
	form := NewMultiPartForm()
	metadata := FileMetadata{
		ContentType: "image/jpeg",
		Filename:    "test.jpg",
	}
	form.SetFileMetadata("avatar", metadata)

	// Test GetFileMetadata for existing field
	retrievedMetadata, exists := form.GetFileMetadata("avatar")
	assert.True(t, exists)
	assert.Equal(t, metadata.ContentType, retrievedMetadata.ContentType)
	assert.Equal(t, metadata.Filename, retrievedMetadata.Filename)

	// Test GetFileMetadata for non-existing field
	_, exists = form.GetFileMetadata("nonexistent")
	assert.False(t, exists)
}

func TestMultiPartForm_FilesMetadataInitialization(t *testing.T) {
	form := NewMultiPartForm()
	assert.NotNil(t, form.filesMetadata)

	metadata := FileMetadata{
		ContentType: "text/plain",
		Filename:    "test.txt",
	}
	form.SetFileMetadata("file", metadata)

	retrievedMetadata, exists := form.GetFileMetadata("file")
	assert.True(t, exists)
	assert.Equal(t, metadata, retrievedMetadata)
}

func TestMultiPartForm_BoundaryValidation(t *testing.T) {
	form := NewMultiPartForm()

	// Test valid boundary
	err := form.ParseBoundary("multipart/form-data; boundary=testboundary")
	assert.NoError(t, err)
	assert.Equal(t, "testboundary", form.boundary)

	// Test missing boundary
	err = form.ParseBoundary("multipart/form-data")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no boundary found")

	// Test boundary too long (over 70 characters)
	longBoundary := "multipart/form-data; boundary=" + string(make([]byte, 71))
	for i := range longBoundary[len("multipart/form-data; boundary="):] {
		longBoundary = longBoundary[:len("multipart/form-data; boundary=")+i] + "a" + longBoundary[len("multipart/form-data; boundary=")+i+1:]
	}

	err = form.ParseBoundary(longBoundary)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "boundary exceeds maximum length")
}

func TestMultiPartForm_DecodeRequiresBoundary(t *testing.T) {
	form := NewMultiPartForm()

	// Decode should fail if boundary is not set
	_, err := form.Decode("some data")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "boundary not set")
}

func TestMultiPartForm_MultipleFilesMetadata(t *testing.T) {
	form := NewMultiPartForm()
	form.boundary = "----WebKitFormBoundaryMultiFileTest"

	// Test with multiple files having the same field name
	multipartData := `------WebKitFormBoundaryMultiFileTest
Content-Disposition: form-data; name="documents"; filename="file1.txt"
Content-Type: text/plain

content1
------WebKitFormBoundaryMultiFileTest
Content-Disposition: form-data; name="documents"; filename="file2.txt"
Content-Type: text/plain

content2
------WebKitFormBoundaryMultiFileTest--
`

	decoded, err := form.Decode(multipartData)
	require.NoError(t, err)

	// Verify files are decoded correctly
	documents := decoded.Get("documents")
	require.NotNil(t, documents)
	documentsArray, ok := documents.([]interface{})
	require.True(t, ok)
	require.Len(t, documentsArray, 2)
	assert.Contains(t, documentsArray, "content1")
	assert.Contains(t, documentsArray, "content2")

	// Verify metadata for the field exists (should be from the first file)
	metadata, exists := form.GetFileMetadata("documents")
	assert.True(t, exists)
	assert.Equal(t, "text/plain", metadata.ContentType)
	assert.Equal(t, "file1.txt", metadata.Filename) // Should be from first file, not last
}

func TestMultiPartForm_SetFileMetadataWithNilMap(t *testing.T) {
	form := &MultiPartForm{}

	// SetFileMetadata should handle nil filesMetadata
	metadata := FileMetadata{
		ContentType: "application/pdf",
		Filename:    "document.pdf",
	}
	form.SetFileMetadata("doc", metadata)

	// Should be able to retrieve the metadata
	retrievedMetadata, exists := form.GetFileMetadata("doc")
	assert.True(t, exists)
	assert.Equal(t, metadata, retrievedMetadata)
}

func TestMultiPartForm_GetFileMetadataWithNilMap(t *testing.T) {
	form := &MultiPartForm{}

	// GetFileMetadata should handle nil filesMetadata gracefully
	_, exists := form.GetFileMetadata("anything")
	assert.False(t, exists)
}
