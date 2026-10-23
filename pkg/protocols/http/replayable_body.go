package http

import (
	"io"
	"strings"

	"github.com/projectdiscovery/retryablehttp-go"
)

type replayableStringBody struct {
	reader *strings.Reader
	value  string
}

func (body *replayableStringBody) Read(dst []byte) (int, error) {
	n, err := body.reader.Read(dst)
	if err == io.EOF {
		body.reader.Reset(body.value)
	}
	return n, err
}

func (body *replayableStringBody) Close() error {
	return nil
}

func setReplayableStringBody(request *retryablehttp.Request, value string) {
	size := int64(len(value))
	request.Body = &replayableStringBody{reader: strings.NewReader(value), value: value}
	request.GetBody = func() (io.ReadCloser, error) {
		return &replayableStringBody{reader: strings.NewReader(value), value: value}, nil
	}
	request.ContentLength = size
}
