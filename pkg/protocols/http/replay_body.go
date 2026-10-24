package http

import (
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/projectdiscovery/retryablehttp-go"
)

type ReplayPart struct {
	Pattern string
	Count   int64
}

type replaySection struct {
	pattern string
	length  int64
}

type ReplayBody struct {
	sections []replaySection
	length   int64
}

func NewReplayBody(parts []ReplayPart, trimTail int64) (*ReplayBody, error) {
	if trimTail < 0 {
		return nil, fmt.Errorf("negative replay body tail trim")
	}
	body := &ReplayBody{sections: make([]replaySection, 0, len(parts))}
	for _, part := range parts {
		if part.Count < 0 {
			return nil, fmt.Errorf("negative replay body repeat count")
		}
		if len(part.Pattern) == 0 || part.Count == 0 {
			continue
		}
		if part.Count > math.MaxInt64/int64(len(part.Pattern)) {
			return nil, fmt.Errorf("replay body length overflow")
		}
		length := int64(len(part.Pattern)) * part.Count
		if body.length > math.MaxInt64-length {
			return nil, fmt.Errorf("replay body length overflow")
		}
		body.sections = append(body.sections, replaySection{pattern: part.Pattern, length: length})
		body.length += length
	}
	if trimTail > body.length {
		return nil, fmt.Errorf("replay body tail trim exceeds length")
	}
	body.length -= trimTail
	if body.length > math.MaxInt64-2 {
		return nil, fmt.Errorf("replay body length overflow")
	}
	remaining := body.length
	for index := range body.sections {
		section := &body.sections[index]
		if remaining >= section.length {
			remaining -= section.length
			continue
		}
		section.length = remaining
		body.sections = body.sections[:index+1]
		break
	}
	return body, nil
}

func (body *ReplayBody) Len() int64 {
	return body.length
}

func (body *ReplayBody) NewReader() io.ReadCloser {
	readers := make([]io.Reader, 0, len(body.sections))
	for _, section := range body.sections {
		readers = append(readers, &repeatSectionReader{section: section})
	}
	return io.NopCloser(io.MultiReader(readers...))
}

func (body *ReplayBody) appendLiteral(value string) *ReplayBody {
	if value == "" {
		return body
	}
	copyBody := &ReplayBody{
		sections: make([]replaySection, 0, len(body.sections)+1),
		length:   body.length + int64(len(value)),
	}
	copyBody.sections = append(copyBody.sections, body.sections...)
	copyBody.sections = append(copyBody.sections, replaySection{pattern: value, length: int64(len(value))})
	return copyBody
}

type repeatSectionReader struct {
	section replaySection
	read    int64
}

func (reader *repeatSectionReader) Read(dst []byte) (int, error) {
	if reader.read >= reader.section.length {
		return 0, io.EOF
	}
	remaining := reader.section.length - reader.read
	if int64(len(dst)) > remaining {
		dst = dst[:int(remaining)]
	}
	if len(dst) == 0 {
		return 0, nil
	}
	pattern := reader.section.pattern
	offset := reader.read % int64(len(pattern))
	n := copy(dst, pattern[offset:])
	if n < len(dst) {
		n += copy(dst[n:], pattern[:offset])
	}
	for n < len(dst) {
		n += copy(dst[n:], dst[:n])
	}
	reader.read += int64(len(dst))
	return len(dst), nil
}

type replayableStreamBody struct {
	reader io.ReadCloser
	source *ReplayBody
}

func newReplayableStreamBody(source *ReplayBody) *replayableStreamBody {
	return &replayableStreamBody{reader: source.NewReader(), source: source}
}

func (body *replayableStreamBody) Read(dst []byte) (int, error) {
	n, err := body.reader.Read(dst)
	if err == io.EOF {
		if closeErr := body.reader.Close(); closeErr != nil {
			return n, closeErr
		}
		body.reader = body.source.NewReader()
	}
	return n, err
}

func (body *replayableStreamBody) Close() error {
	return body.reader.Close()
}

func setReplayBody(request *retryablehttp.Request, source *ReplayBody) {
	request.Body = newReplayableStreamBody(source)
	request.GetBody = func() (io.ReadCloser, error) {
		return newReplayableStreamBody(source), nil
	}
	request.ContentLength = source.Len()
}

func replayBodyPlaceholder(text string, values map[string]interface{}) (*ReplayBody, bool) {
	var suffix string
	if strings.HasSuffix(text, "\r\n") {
		text, suffix = strings.TrimSuffix(text, "\r\n"), "\r\n"
	} else if strings.HasSuffix(text, "\n") {
		text, suffix = strings.TrimSuffix(text, "\n"), "\n"
	}
	if !strings.HasPrefix(text, "{{") || !strings.HasSuffix(text, "}}") {
		return nil, false
	}
	name := strings.TrimSpace(text[2 : len(text)-2])
	body, ok := values[name].(*ReplayBody)
	if !ok {
		return nil, false
	}
	return body.appendLiteral(suffix), true
}
