package json

import (
	"bytes"
	stdjson "encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

// JSONFormat is a JSON format parser for nuclei
// input HTTP requests
type JSONFormat struct {
	opts formats.InputFormatOptions
}

// New creates a new JSON format parser
func New() *JSONFormat {
	return &JSONFormat{}
}

var _ formats.Format = &JSONFormat{}
var _ formats.MetaInputFormat = &JSONFormat{}

// proxifyRequest is a request for proxify
type proxifyRequest struct {
	URL     string `json:"url"`
	Request struct {
		Header   map[string]string `json:"header"`
		Body     string            `json:"body"`
		Raw      string            `json:"raw"`
		Endpoint string            `json:"endpoint"`
	} `json:"request"`
}

type targetRequest struct {
	URL         string    `json:"url"`
	Tags        *[]string `json:"tags"`
	ExcludeTags *[]string `json:"exclude-tags"`
	Severity    *[]string `json:"severity"`
	Templates   *[]string `json:"templates"`
}

// Name returns the name of the format
func (j *JSONFormat) Name() string {
	return "jsonl"
}

func (j *JSONFormat) SetOptions(options formats.InputFormatOptions) {
	j.opts = options
}

// Parse parses the input and calls the provided callback
// function for each RawRequest it discovers.
func (j *JSONFormat) Parse(input io.Reader, resultsCb formats.ParseReqRespCallback, filePath string) error {
	decoder := json.NewDecoder(input)
	for {
		var request proxifyRequest
		err := decoder.Decode(&request)
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "could not decode json file")
		}

		if request.URL == "" && request.Request.Endpoint != "" {
			request.URL = request.Request.Endpoint
		}
		rawRequest, err := types.ParseRawRequestWithURL(request.Request.Raw, request.URL)
		if err != nil {
			gologger.Warning().Msgf("jsonl: Could not parse raw request %s: %s\n", request.URL, err)
			continue
		}
		resultsCb(rawRequest)
	}
	return nil
}

// ParseMeta parses either legacy Proxify JSONL records or per-target JSONL
// records. Mixing both record kinds in the same file is rejected because they
// require different execution modes.
func (j *JSONFormat) ParseMeta(input io.Reader, resultsCb formats.ParseMetaInputCallback, _ string) error {
	tracker := &lineTrackingReader{reader: input}
	decoder := stdjson.NewDecoder(tracker)
	recordKind := ""

	for {
		var raw stdjson.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			lineNumber := tracker.lineAt(decoder.InputOffset())
			if syntaxErr, ok := err.(*stdjson.SyntaxError); ok {
				lineNumber = tracker.lineAt(syntaxErr.Offset - 1)
			}
			return fmt.Errorf("jsonl line %d: invalid JSON: %w", lineNumber, err)
		}
		lineNumber := tracker.lineAt(decoder.InputOffset() - int64(len(raw)))

		var fields map[string]stdjson.RawMessage
		if err := stdjson.Unmarshal(raw, &fields); err != nil {
			return fmt.Errorf("jsonl line %d: each record must be a JSON object: %w", lineNumber, err)
		}

		kind := recordType(fields)
		if kind == "proxify" {
			for _, name := range []string{"tags", "exclude-tags", "severity", "templates"} {
				if _, ok := fields[name]; ok {
					return fmt.Errorf("jsonl line %d: Proxify request records cannot include target filter field %q", lineNumber, name)
				}
			}
		}
		if recordKind == "" {
			recordKind = kind
		} else if recordKind != kind {
			return fmt.Errorf("jsonl line %d: cannot mix %s and %s records in one input file", lineNumber, recordKind, kind)
		}

		var metaInput *contextargs.MetaInput
		var err error
		switch kind {
		case "proxify":
			metaInput, err = parseProxifyMetaInput(raw)
		default:
			metaInput, err = parseTargetMetaInput(raw, fields, lineNumber)
		}
		if err != nil {
			return err
		}
		if metaInput != nil && !resultsCb(metaInput) {
			return nil
		}
	}
	return nil
}

type lineTrackingReader struct {
	reader   io.Reader
	offset   int64
	newlines []int64
}

func (r *lineTrackingReader) Read(data []byte) (int, error) {
	read, err := r.reader.Read(data)
	for index, value := range data[:read] {
		if value == '\n' {
			r.newlines = append(r.newlines, r.offset+int64(index))
		}
	}
	r.offset += int64(read)
	return read, err
}

func (r *lineTrackingReader) lineAt(offset int64) int {
	if offset < 0 {
		offset = 0
	}
	return sort.Search(len(r.newlines), func(index int) bool {
		return r.newlines[index] >= offset
	}) + 1
}

func recordType(fields map[string]stdjson.RawMessage) string {
	rawRequest, ok := fields["request"]
	if !ok {
		return "target"
	}
	var requestFields map[string]stdjson.RawMessage
	if err := stdjson.Unmarshal(rawRequest, &requestFields); err != nil {
		return "target"
	}
	for _, name := range []string{"header", "body", "raw", "endpoint"} {
		if _, ok := requestFields[name]; ok {
			return "proxify"
		}
	}
	return "target"
}

func parseProxifyMetaInput(data []byte) (*contextargs.MetaInput, error) {
	var request proxifyRequest
	if err := stdjson.Unmarshal(data, &request); err != nil {
		return nil, fmt.Errorf("could not decode Proxify JSONL record: %w", err)
	}
	if request.URL == "" && request.Request.Endpoint != "" {
		request.URL = request.Request.Endpoint
	}
	rawRequest, err := types.ParseRawRequestWithURL(request.Request.Raw, request.URL)
	if err != nil {
		gologger.Warning().Msgf("jsonl: Could not parse raw request %s: %s\n", request.URL, err)
		return nil, nil
	}
	metaInput := contextargs.NewMetaInput()
	metaInput.ReqResp = rawRequest
	metaInput.Input = rawRequest.URL.String()
	return metaInput, nil
}

func parseTargetMetaInput(data []byte, fields map[string]stdjson.RawMessage, lineNumber int) (*contextargs.MetaInput, error) {
	for name, raw := range fields {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, fmt.Errorf("jsonl line %d: field %q must not be null", lineNumber, name)
		}
	}

	decoder := stdjson.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var target targetRequest
	if err := decoder.Decode(&target); err != nil {
		return nil, fmt.Errorf("jsonl line %d: invalid target record: %w", lineNumber, err)
	}
	if strings.TrimSpace(target.URL) == "" {
		return nil, fmt.Errorf("jsonl line %d: field %q is required and must not be empty", lineNumber, "url")
	}

	filter := &contextargs.TargetFilter{SourceLine: lineNumber}
	var err error
	if target.Tags != nil {
		filter.HasTags = true
		filter.Tags, err = normalizeValues(*target.Tags, true, "tags", lineNumber)
		if err != nil {
			return nil, err
		}
	}
	if target.ExcludeTags != nil {
		filter.HasExcludeTags = true
		filter.ExcludeTags, err = normalizeValues(*target.ExcludeTags, true, "exclude-tags", lineNumber)
		if err != nil {
			return nil, err
		}
	}
	if target.Severity != nil {
		filter.HasSeverities = true
		normalized, normalizeErr := normalizeValues(*target.Severity, true, "severity", lineNumber)
		if normalizeErr != nil {
			return nil, normalizeErr
		}
		for _, value := range normalized {
			encoded, _ := stdjson.Marshal(value)
			var holder severity.Holder
			if err := holder.UnmarshalJSON(encoded); err != nil {
				return nil, fmt.Errorf("jsonl line %d: invalid severity %q: %w", lineNumber, value, err)
			}
			filter.Severities = append(filter.Severities, holder.Severity)
		}
	}
	if target.Templates != nil {
		filter.HasTemplates = true
		filter.Templates, err = normalizeValues(*target.Templates, false, "templates", lineNumber)
		if err != nil {
			return nil, err
		}
	}

	metaInput := contextargs.NewMetaInput()
	metaInput.Input = strings.TrimSpace(target.URL)
	metaInput.TargetFilter = filter
	return metaInput, nil
}

func normalizeValues(values []string, lowercase bool, field string, lineNumber int) ([]string, error) {
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf("jsonl line %d: field %q contains an empty value at index %d", lineNumber, field, index)
		}
		if lowercase {
			value = strings.ToLower(value)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized, nil
}
