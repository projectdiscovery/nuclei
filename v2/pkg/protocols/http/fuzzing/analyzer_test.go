package fuzzing

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFuzzingAnalyzeRequest(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.com", nil)
	require.Nil(t, err, "could not create http request")

	buffer := new(bytes.Buffer)
	writer := multipart.NewWriter(buffer)
	part, err := writer.CreateFormFile("file", "file.txt")
	if err != nil {
		require.Nil(t, err, "could not create form")
	}
	_, err = io.Copy(part, strings.NewReader("hello world"))

	params := map[string]string{"test": "value", "form": "data"}
	for key, val := range params {
		_ = writer.WriteField(key, val)
	}
	writer.Close()
	req.Body = ioutil.NopCloser(buffer)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Content-Length", strconv.Itoa(buffer.Len()))

	normalized, err := NormalizeRequest(req)
	require.Nil(t, err, "could not create normalized request")

	err = AnalyzeRequest(normalized, &AnalyzerOptions{}, func(req *http.Request) {
		if data, err := httputil.DumpRequestOut(req, true); err == nil {
			fmt.Printf("%v\n", string(data))
		}
	})
	require.Nil(t, err, "could not analyze normalized request")
}
