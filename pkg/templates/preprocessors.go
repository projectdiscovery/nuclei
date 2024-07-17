package templates

import (
	"bytes"
	"regexp"
	"strings"

	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/segmentio/ksuid"
)

type Preprocessor interface {
	// Process processes the data and returns the processed data.
	ProcessNReturnData(data []byte) ([]byte, map[string]interface{})
	// Exists check if the preprocessor exists in the data.
	Exists(data []byte) bool
}

var (
	preprocessorRegex    = regexp.MustCompile(`{{([a-z0-9_]+)}}`)
	defaultPreprocessors = []Preprocessor{
		&randStrPreprocessor{},
	}
)

func getPreprocessors(preprocessor Preprocessor) []Preprocessor {
	if preprocessor != nil {
		// append() function adds the elements to existing slice if space is available
		// else it creates a new slice and copies the elements to new slice
		// this may cause race-conditions hence we do it explicitly
		tmp := make([]Preprocessor, 0, len(defaultPreprocessors)+1)
		tmp = append(tmp, preprocessor)
		tmp = append(tmp, defaultPreprocessors...)
		return tmp
	}
	return defaultPreprocessors
}

var _ Preprocessor = &randStrPreprocessor{}

type randStrPreprocessor struct{}

// ProcessNReturnData processes the data and returns the key-value pairs of generated/replaced data.
func (r *randStrPreprocessor) ProcessNReturnData(data []byte) ([]byte, map[string]interface{}) {
	foundMap := make(map[string]struct{})
	dataMap := make(map[string]interface{})
	for _, expression := range preprocessorRegex.FindAllStringSubmatch(string(data), -1) {
		if len(expression) != 2 {
			continue
		}
		value := expression[1]
		if stringsutil.ContainsAny(value, "(", ")") {
			continue
		}

		if _, ok := foundMap[value]; ok {
			continue
		}
		foundMap[value] = struct{}{}
		if strings.EqualFold(value, "randstr") || strings.HasPrefix(value, "randstr_") {
			randStr := ksuid.New().String()
			data = bytes.ReplaceAll(data, []byte(expression[0]), []byte(randStr))
			dataMap[expression[0]] = randStr
		}
	}
	return data, dataMap
}

// Exists check if the preprocessor exists in the data.
func (r *randStrPreprocessor) Exists(data []byte) bool {
	return bytes.Contains(data, []byte("randstr"))
}
