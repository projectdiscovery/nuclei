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
	return &MultiPartForm{}
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

		if filesArray, ok := value.([]interface{}); ok {
			fileMetadata, ok := m.filesMetadata[key]
			if !ok {
				Itererr = fmt.Errorf("file metadata not found for key %s", key)
				return false
			}

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

		// Add field
		if fw, err = w.CreateFormField(key); err != nil {
			Itererr = err
			return false
		}

		if _, err = fw.Write([]byte(value.(string))); err != nil {
			Itererr = err
			return false
		}
		return true
	})
	if Itererr != nil {
		return "", Itererr
	}

	w.Close()
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
	return nil
}

// Decode decodes the data from MultiPartForm format
func (m *MultiPartForm) Decode(data string) (KV, error) {
	// Create a buffer from the string data
	b := bytes.NewBufferString(data)
	// The boundary parameter should be extracted from the Content-Type header of the HTTP request
	// which is not available in this context, so this is a placeholder for demonstration.
	// You will need to pass the actual boundary value to this function.
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
	m.filesMetadata = make(map[string]FileMetadata)
	for key, files := range form.File {
		fileContents := []interface{}{}
		for _, fileHeader := range files {
			file, err := fileHeader.Open()
			if err != nil {
				return KV{}, err
			}
			defer file.Close()

			buffer := new(bytes.Buffer)
			if _, err := buffer.ReadFrom(file); err != nil {
				return KV{}, err
			}
			fileContents = append(fileContents, buffer.String())

			m.filesMetadata[key] = FileMetadata{
				ContentType: fileHeader.Header.Get("Content-Type"),
				Filename:    fileHeader.Filename,
			}
		}
		result.Set(key, fileContents)
	}
	return KVOrderedMap(&result), nil
}

// Name returns the name of the encoder
func (m *MultiPartForm) Name() string {
	return "multipart/form-data"
}
