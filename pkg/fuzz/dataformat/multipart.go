package dataformat

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"

	mapsutil "github.com/projectdiscovery/utils/maps"
)

type MultiPartForm struct {
	boundary      string
	filesMetadata map[string]FileMetadata
}

type FileMetadata struct {
	ContentType string
	Filename    string
}

var (
	_ DataFormat = &MultiPartForm{}
)

// NewMultiPartForm returns a new MultiPartForm encoder
func NewMultiPartForm() *MultiPartForm {
	return &MultiPartForm{
		filesMetadata: make(map[string]FileMetadata),
	}
}

// SetFileMetadata sets the file metadata for a given field name
func (m *MultiPartForm) SetFileMetadata(fieldName string, metadata FileMetadata) {
	if m.filesMetadata == nil {
		m.filesMetadata = make(map[string]FileMetadata)
	}

	m.filesMetadata[fieldName] = metadata
}

// GetFileMetadata gets the file metadata for a given field name
func (m *MultiPartForm) GetFileMetadata(fieldName string) (FileMetadata, bool) {
	if m.filesMetadata == nil {
		return FileMetadata{}, false
	}

	metadata, exists := m.filesMetadata[fieldName]

	return metadata, exists
}

// IsType returns true if the data is MultiPartForm encoded
func (m *MultiPartForm) IsType(data string) bool {
	// This method should be implemented to detect if the data is multipart form encoded
	return false
}

// Encode encodes the data into MultiPartForm format
func (m *MultiPartForm) Encode(data KV) (string, error) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	if err := w.SetBoundary(m.boundary); err != nil {
		return "", err
	}

	var Itererr error
	data.Iterate(func(key string, value any) bool {
		var fw io.Writer
		var err error

		if fileMetadata, ok := m.filesMetadata[key]; ok {
			if filesArray, isArray := value.([]any); isArray {
				for _, file := range filesArray {
					h := make(textproto.MIMEHeader)
					h.Set("Content-Disposition",
						fmt.Sprintf(`form-data; name=%q; filename=%q`,
							key, fileMetadata.Filename))
					h.Set("Content-Type", fileMetadata.ContentType)

					if fw, err = w.CreatePart(h); err != nil {
						Itererr = err
						return false
					}

					if _, err = fw.Write([]byte(file.(string))); err != nil {
						Itererr = err
						return false
					}
				}

				return true
			}
		}

		// Add field
		var values []string
		switch v := value.(type) {
		case nil:
			values = []string{""}
		case string:
			values = []string{v}
		case []string:
			values = v
		case []any:
			values = make([]string, len(v))
			for i, item := range v {
				if item == nil {
					values[i] = ""
				} else {
					values[i] = fmt.Sprint(item)
				}
			}
		default:
			values = []string{fmt.Sprintf("%v", v)}
		}

		for _, val := range values {
			if fw, err = w.CreateFormField(key); err != nil {
				Itererr = err
				return false
			}
			if _, err = fw.Write([]byte(val)); err != nil {
				Itererr = err
				return false
			}
		}
		return true
	})
	if Itererr != nil {
		return "", Itererr
	}

	_ = w.Close()
	return b.String(), nil
}

// ParseBoundary parses the boundary from the content type
func (m *MultiPartForm) ParseBoundary(contentType string) error {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return err
	}
	m.boundary = params["boundary"]
	if m.boundary == "" {
		return fmt.Errorf("no boundary found in the content type")
	}

	// NOTE(dwisiswant0): boundary cannot exceed 70 characters according to
	// RFC-2046.
	if len(m.boundary) > 70 {
		return fmt.Errorf("boundary exceeds maximum length of 70 characters")
	}

	return nil
}

// Decode decodes the data from MultiPartForm format
func (m *MultiPartForm) Decode(data string) (KV, error) {
	if m.boundary == "" {
		return KV{}, fmt.Errorf("boundary not set, call ParseBoundary first")
	}

	// Create a buffer from the string data
	b := bytes.NewBufferString(data)
	r := multipart.NewReader(b, m.boundary)

	form, err := r.ReadForm(32 << 20) // 32MB is the max memory used to parse the form
	if err != nil {
		return KV{}, err
	}
	defer func() {
		_ = form.RemoveAll()
	}()

	result := mapsutil.NewOrderedMap[string, any]()
	for key, values := range form.Value {
		if len(values) > 1 {
			result.Set(key, values)
		} else {
			result.Set(key, values[0])
		}
	}

	if m.filesMetadata == nil {
		m.filesMetadata = make(map[string]FileMetadata)
	}

	for key, files := range form.File {
		fileContents := []interface{}{}
		var fileMetadataList []FileMetadata

		for _, fileHeader := range files {
			file, err := fileHeader.Open()
			if err != nil {
				return KV{}, err
			}

			buffer := new(bytes.Buffer)
			if _, err := buffer.ReadFrom(file); err != nil {
				file.Close()

				return KV{}, err
			}
			file.Close()

			fileContents = append(fileContents, buffer.String())

			fileMetadataList = append(fileMetadataList, FileMetadata{
				ContentType: fileHeader.Header.Get("Content-Type"),
				Filename:    fileHeader.Filename,
			})
		}

		result.Set(key, fileContents)

		// NOTE(dwisiswant0): store the first file's metadata instead of the
		// last one
		if len(fileMetadataList) > 0 {
			m.filesMetadata[key] = fileMetadataList[0]
		}
	}
	return KVOrderedMap(&result), nil
}

// Name returns the name of the encoder
func (m *MultiPartForm) Name() string {
	return "multipart/form-data"
}
