package requests

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/projectdiscovery/retryablehttp-go"
)

func newReplacer(values map[string]interface{}) *strings.Replacer {
	var replacerItems []string
	for k, v := range values {
		replacerItems = append(replacerItems, fmt.Sprintf("{{%s}}", k))
		replacerItems = append(replacerItems, fmt.Sprintf("%s", v))
	}

	return strings.NewReplacer(replacerItems...)
}

// HandleDecompression if the user specified a custom encoding (as golang transport doesn't do this automatically)
func HandleDecompression(r *retryablehttp.Request, bodyOrig []byte) (bodyDec []byte, err error) {
	encodingHeader := strings.ToLower(r.Header.Get("Accept-Encoding"))
	if encodingHeader == "gzip" {
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
