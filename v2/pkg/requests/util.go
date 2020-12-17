package requests

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"strings"
)

const (
	markerParenthesisOpen  = "{{"
	markerParenthesisClose = "}}"
	markerGeneral          = "§"
)

func newReplacer(values map[string]interface{}) *strings.Replacer {
	var replacerItems []string
	for key, val := range values {
		replacerItems = append(
			replacerItems,
			fmt.Sprintf("%s%s%s", markerParenthesisOpen, key, markerParenthesisClose),
			fmt.Sprintf("%s", val),
			fmt.Sprintf("%s%s%s", markerGeneral, key, markerGeneral),
			fmt.Sprintf("%s", val),
		)
	}

	return strings.NewReplacer(replacerItems...)
}

// HandleDecompression if the user specified a custom encoding (as golang transport doesn't do this automatically)
func HandleDecompression(r *HTTPRequest, bodyOrig []byte) (bodyDec []byte, err error) {
	if r.Request == nil {
		return bodyOrig, nil
	}

	encodingHeader := strings.TrimSpace(strings.ToLower(r.Request.Header.Get("Accept-Encoding")))
	if encodingHeader == "gzip" || encodingHeader == "gzip, deflate" {
		gzipreader, err := gzip.NewReader(bytes.NewReader(bodyOrig))
		if err != nil {
			return bodyDec, err
		}
		defer gzipreader.Close()

		bodyDec, err = ioutil.ReadAll(gzipreader)
		if err != nil {
			return bodyDec, err
		}

		return bodyDec, nil
	}

	return bodyOrig, nil
}

// ZipMapValues converts values from strings slices to flat string
func ZipMapValues(m map[string][]string) (m1 map[string]string) {
	m1 = make(map[string]string)
	for k, v := range m {
		m1[k] = strings.Join(v, "")
	}
	return
}

// ExpandMapValues converts values from flat string to strings slice
func ExpandMapValues(m map[string]string) (m1 map[string][]string) {
	m1 = make(map[string][]string)
	for k, v := range m {
		m1[k] = []string{v}
	}
	return
}

func hasMarker(s string) bool {
	return strings.Contains(s, markerParenthesisOpen) || strings.Contains(s, markerParenthesisClose) || strings.Contains(s, markerGeneral)
}
