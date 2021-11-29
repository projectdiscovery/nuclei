package templates

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/segmentio/ksuid"
)

type Preprocessor interface {
	Process(data []byte) []byte
}

var preprocessorRegex = regexp.MustCompile(`{{([a-z0-9_]+)}}`)

// expandPreprocessors expands the pre-processors if any for a template data.
func (template *Template) expandPreprocessors(data []byte) []byte {
	foundMap := make(map[string]struct{})

	for _, expression := range preprocessorRegex.FindAllStringSubmatch(string(data), -1) {
		if len(expression) != 2 {
			continue
		}
		value := expression[1]
		if strings.Contains(value, "(") || strings.Contains(value, ")") {
			continue
		}

		if _, ok := foundMap[value]; ok {
			continue
		}
		foundMap[value] = struct{}{}
		if strings.EqualFold(value, "randstr") || strings.HasPrefix(value, "randstr_") {
			data = bytes.ReplaceAll(data, []byte(expression[0]), []byte(ksuid.New().String()))
		}
	}
	return data
}
