package templates

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	nucleiTypes "github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
	"github.com/projectdiscovery/ratelimit"
)

const (
	fuzzMaxInputSize  = 16 << 10
	fuzzMaxValueBytes = 256
)

var (
	fuzzTemplateSeverities = []string{"info", "low", "medium", "high", "critical", "unknown"}
	fuzzTemplateMethods    = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"}
	fuzzTemplatePaths      = []string{"/", "/login", "/api/v1/users", "/search?q=nuclei", "/admin/{{id}}"}
	fuzzTemplateWords      = []string{"nuclei", "Example Domain", "HTTP", "success", "admin"}
	errFuzzHelperDisabled  = errors.New("fuzz template helper file loading disabled")
	fuzzProtocolInit       sync.Once
)

type fuzzTemplateCandidate struct {
	id            string
	name          string
	author        string
	severity      string
	method        string
	path          string
	matcherWord   string
	useRawRequest bool
}

func fuzzTemplateParsing(data []byte) bool {
	if len(data) == 0 || len(data) > fuzzMaxInputSize {
		return false
	}

	candidate := newFuzzTemplateCandidate(data)
	candidate.applyLines(splitFuzzLines(data))

	parsed := exerciseFuzzYAMLTemplate(candidate.yaml())
	if exerciseFuzzJSONTemplate(candidate.json()) {
		parsed = true
	}

	exerciseFuzzDirectTemplateParsers(data)
	return parsed
}

func exerciseFuzzYAMLTemplate(data []byte) bool {
	return exerciseFuzzYAMLTemplateErr(data) == nil
}

func exerciseFuzzYAMLTemplateErr(data []byte) error {
	template, err := parseFuzzYAMLTemplate(data)
	if err != nil {
		return err
	}
	exerciseFuzzParsedTemplate(template)
	if _, err = compileFuzzTemplate(data); err != nil {
		return err
	}
	return nil
}

func exerciseFuzzJSONTemplate(data []byte) bool {
	return exerciseFuzzJSONTemplateErr(data) == nil
}

func exerciseFuzzJSONTemplateErr(data []byte) error {
	template, err := parseFuzzJSONTemplate(data)
	if err != nil {
		return err
	}
	exerciseFuzzParsedTemplate(template)
	if _, err = compileFuzzTemplate(data); err != nil {
		return err
	}
	return nil
}

func exerciseFuzzDirectTemplateParsers(data []byte) {
	if len(bytes.TrimSpace(data)) == 0 {
		return
	}

	if template, err := parseFuzzYAMLTemplate(data); err == nil {
		exerciseFuzzParsedTemplate(template)
	}
	if json.Valid(data) {
		if template, err := parseFuzzJSONTemplate(data); err == nil {
			exerciseFuzzParsedTemplate(template)
		}
	}
}

func parseFuzzYAMLTemplate(data []byte) (*Template, error) {
	template := &Template{}
	if err := yaml.UnmarshalStrict(data, template); err != nil {
		return nil, err
	}
	if err := validateTemplateMandatoryFields(template); err != nil {
		return nil, err
	}
	return template, nil
}

func parseFuzzJSONTemplate(data []byte) (*Template, error) {
	template := &Template{}
	if err := template.unmarshalJSONStrict(data); err != nil {
		return nil, err
	}
	if err := validateTemplateMandatoryFields(template); err != nil {
		return nil, err
	}
	return template, nil
}

func compileFuzzTemplate(data []byte) (*Template, error) {
	template, err := parseTemplateNoVerify(data, newFuzzExecutorOptions())
	if err != nil {
		return nil, err
	}
	if template == nil {
		return nil, errors.New("nil compiled template")
	}
	exerciseFuzzParsedTemplate(template)
	return template, nil
}

func exerciseFuzzParsedTemplate(template *Template) {
	if template == nil {
		panic("nil template")
	}
	_ = template.Type()
	_ = template.Requests()
	template.validateAllRequestIDs()
	template.parseSelfContainedRequests()
}

func newFuzzExecutorOptions() *protocols.ExecutorOptions {
	options := nucleiTypes.DefaultOptions()
	options.NoColor = true
	options.RateLimit = 1
	options.RateLimitDuration = time.Second
	options.BulkSize = 1
	options.TemplateThreads = 1
	options.PayloadConcurrency = 1
	options.TemplateLoadingConcurrency = 1
	options.ExecutionId = "fuzz-template"
	options.LoadHelperFileFunction = func(string, string, catalog.Catalog) (io.ReadCloser, error) {
		return nil, errFuzzHelperDisabled
	}
	fuzzProtocolInit.Do(func() {
		_ = protocolstate.Init(options)
		_ = protocolinit.Init(options)
	})

	executorOptions := &protocols.ExecutorOptions{
		Options:      options,
		Catalog:      disk.NewCatalog(""),
		RateLimiter:  ratelimit.New(context.Background(), 1, time.Second),
		Parser:       NewParser(),
		DoNotCache:   true,
		TemplatePath: "fuzz-template.yaml",
	}
	executorOptions.CreateTemplateCtxStore()
	return executorOptions
}

func newFuzzTemplateCandidate(data []byte) *fuzzTemplateCandidate {
	flags := fuzzByteAt(data, 1)
	return &fuzzTemplateCandidate{
		id:            fuzzTemplateID(string(data)),
		name:          "fuzz template",
		author:        "nuclei-fuzzer",
		severity:      fuzzTemplateSeverities[int(fuzzByteAt(data, 0))%len(fuzzTemplateSeverities)],
		method:        fuzzTemplateMethods[int(fuzzByteAt(data, 2))%len(fuzzTemplateMethods)],
		path:          fuzzTemplatePaths[int(fuzzByteAt(data, 3))%len(fuzzTemplatePaths)],
		matcherWord:   fuzzTemplateWords[int(fuzzByteAt(data, 4))%len(fuzzTemplateWords)],
		useRawRequest: flags&0x01 != 0,
	}
}

func (candidate *fuzzTemplateCandidate) applyLines(lines []string) {
	for _, line := range lines {
		key, value, ok := cutFuzzKV(line)
		if !ok {
			candidate.matcherWord = fuzzTemplateText(line, candidate.matcherWord)
			continue
		}

		switch key {
		case "id":
			candidate.id = fuzzTemplateID(value)
		case "name":
			candidate.name = fuzzTemplateText(value, candidate.name)
		case "author":
			candidate.author = fuzzTemplateID(value)
		case "severity":
			candidate.severity = fuzzSeverity(value, candidate.severity)
		case "method":
			candidate.method = fuzzMethod(value, candidate.method)
		case "path":
			candidate.path = fuzzPath(value, candidate.path)
		case "matcher", "word":
			candidate.matcherWord = fuzzTemplateText(value, candidate.matcherWord)
		case "raw", "use-raw":
			candidate.useRawRequest = fuzzBool(value, candidate.useRawRequest)
		}
	}
}

func (candidate *fuzzTemplateCandidate) yaml() []byte {
	var builder strings.Builder
	fmt.Fprintf(&builder, "id: %s\n", yamlQuote(candidate.id))
	fmt.Fprintf(&builder, "info:\n  name: %s\n  author: %s\n  severity: %s\n", yamlQuote(candidate.name), yamlQuote(candidate.author), yamlQuote(candidate.severity))
	builder.WriteString("http:\n  - ")
	if candidate.useRawRequest {
		builder.WriteString("raw:\n      - |\n")
		for _, line := range strings.Split(candidate.rawRequest(), "\r\n") {
			if line == "" {
				builder.WriteString("        \n")
				continue
			}
			fmt.Fprintf(&builder, "        %s\n", line)
		}
	} else {
		fmt.Fprintf(&builder, "method: %s\n    path:\n      - %s\n", yamlQuote(candidate.method), yamlQuote("{{BaseURL}}"+candidate.path))
	}
	builder.WriteString("    matchers:\n      - type: word\n        part: body\n        words:\n")
	fmt.Fprintf(&builder, "          - %s\n", yamlQuote(candidate.matcherWord))
	return []byte(builder.String())
}

func (candidate *fuzzTemplateCandidate) json() []byte {
	request := map[string]interface{}{
		"matchers": []map[string]interface{}{
			{
				"type":  "word",
				"part":  "body",
				"words": []string{candidate.matcherWord},
			},
		},
	}
	if candidate.useRawRequest {
		request["raw"] = []string{candidate.rawRequest()}
	} else {
		request["method"] = candidate.method
		request["path"] = []string{"{{BaseURL}}" + candidate.path}
	}

	template := map[string]interface{}{
		"id": candidate.id,
		"info": map[string]interface{}{
			"name":     candidate.name,
			"author":   candidate.author,
			"severity": candidate.severity,
		},
		"http": []map[string]interface{}{request},
	}
	data, err := json.Marshal(template)
	if err != nil {
		panic(err)
	}
	return data
}

func (candidate *fuzzTemplateCandidate) rawRequest() string {
	path := candidate.path
	if path == "" {
		path = "/"
	}
	return fmt.Sprintf("%s %s HTTP/1.1\r\nHost: {{Hostname}}\r\nUser-Agent: nuclei-fuzz\r\n\r\n", candidate.method, path)
}

func splitFuzzLines(data []byte) []string {
	fields := strings.FieldsFunc(string(data), func(r rune) bool {
		return r == '\n' || r == '\r' || r == ';'
	})
	if len(fields) > 32 {
		fields = fields[:32]
	}

	lines := make([]string, 0, len(fields))
	for _, field := range fields {
		field = fuzzTrim(field)
		if field != "" {
			lines = append(lines, field)
		}
	}
	return lines
}

func cutFuzzKV(line string) (string, string, bool) {
	key, value, ok := strings.Cut(line, "=")
	if !ok {
		key, value, ok = strings.Cut(line, ":")
	}
	if !ok {
		return "", "", false
	}
	return strings.ToLower(fuzzTrim(key)), fuzzTrim(value), true
}

func yamlQuote(value string) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func fuzzByteAt(data []byte, index int) byte {
	if len(data) == 0 {
		return 0
	}
	return data[index%len(data)]
}

func fuzzTemplateID(value string) string {
	value = strings.ToLower(fuzzToken(value, 48))
	value = strings.Trim(value, "-_")
	value = strings.ReplaceAll(value, "_-", "-")
	value = strings.ReplaceAll(value, "-_", "-")
	if value == "" {
		return "fuzz-template"
	}
	return value
}

func fuzzTemplateText(value, fallback string) string {
	value = fuzzTrim(value)
	if value == "" {
		return fallback
	}
	return value
}

func fuzzSeverity(value, fallback string) string {
	value = strings.ToLower(fuzzTrim(value))
	for _, severity := range fuzzTemplateSeverities {
		if value == severity {
			return value
		}
	}
	return fallback
}

func fuzzMethod(value, fallback string) string {
	value = strings.ToUpper(fuzzToken(value, 16))
	if value == "" {
		return fallback
	}
	return value
}

func fuzzPath(value, fallback string) string {
	value = fuzzTrim(value)
	if value == "" {
		return fallback
	}
	if !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "?") {
		value = "/" + value
	}
	return value
}

func fuzzBool(value string, fallback bool) bool {
	switch strings.ToLower(fuzzTrim(value)) {
	case "1", "t", "true", "yes", "y", "on":
		return true
	case "0", "f", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func fuzzToken(value string, limit int) string {
	value = fuzzTrim(value)
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			builder.WriteRune(r - 'A' + 'a')
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-' || r == '_':
			builder.WriteRune(r)
		}
		if builder.Len() >= limit {
			break
		}
	}
	return builder.String()
}

func fuzzTrim(value string) string {
	value = strings.TrimSpace(strings.NewReplacer("\x00", "", "\r", " ", "\n", " ").Replace(value))
	if len(value) > fuzzMaxValueBytes {
		value = value[:fuzzMaxValueBytes]
	}
	return value
}
