package dataformat

import (
	"net/url"
)

type Form struct{}

var (
	_ DataFormat = &Form{}
)

// NewForm returns a new Form encoder
func NewForm() *Form {
	return &Form{}
}

// IsType returns true if the data is Form encoded
func (f *Form) IsType(data string) bool {
	return false
}

// Encode encodes the data into Form format
func (f *Form) Encode(data map[string]interface{}) (string, error) {
	query := url.Values{}
	for key, value := range data {
		switch v := value.(type) {
		case []interface{}:
			for _, val := range v {
				query.Add(key, val.(string))
			}
		case string:
			query.Set(key, v)
		}
	}
	encoded := query.Encode()
	return encoded, nil
}

// Decode decodes the data from Form format
func (f *Form) Decode(data string) (map[string]interface{}, error) {
	parsed, err := url.ParseQuery(data)
	if err != nil {
		return nil, err
	}

	values := make(map[string]interface{})
	for key, value := range parsed {
		if len(value) == 1 {
			values[key] = value[0]
		} else {
			values[key] = value
		}
	}
	return values, nil
}

// Name returns the name of the encoder
func (f *Form) Name() string {
	return FormDataFormat
}
