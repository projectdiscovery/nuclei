package extractors

import (
	"regexp"
	"strconv"
	"strings"
)

const (
	fuzzMaxInputSize  = 16 << 10
	fuzzMaxItems      = 8
	fuzzMaxValueBytes = 256
)

var (
	fuzzExtractorTypes = []ExtractorType{RegexExtractor, KValExtractor, XPathExtractor, JSONExtractor, DSLExtractor}
	fuzzParts          = []string{"", "body", "raw", "all_headers", "header", "response"}
	fuzzAttributes     = []string{"", "href", "content", "id", "name"}
	fuzzRegexDefaults  = []string{`([A-Za-z0-9_]+)`, `token=([a-z0-9]+)`, `https?://[^\s"']+`}
	fuzzKValDefaults   = []string{"content_type", "server", "set_cookie", "x_powered_by"}
	fuzzJSONDefaults   = []string{`.id`, `.items[] | .id`, `.headers.server`, `.links[] | .href`}
	fuzzXPathDefaults  = []string{`//title`, `/html/body/div/p[2]/a`, `//link`, `/root/item`, `//item`}
	fuzzDSLDefaults    = []string{`to_upper(hello)`, `contains(to_lower(all_headers), "server")`, `body`, `content_type`}
	fuzzRegexCorpus    = "token=abc123\nserver=nginx\nurl=https://example.com/path\nhello=world"
	fuzzJSONCorpus     = `{"id":1,"name":"nuclei","items":[{"id":"a1"},{"id":"b2"}],"headers":{"server":"nginx"},"links":[{"href":"https://example.com"}]}`
	fuzzHTMLCorpus     = `<!doctype html><html><head><title>Example Domain</title><meta content="text/html" name="description" /></head><body><div><p>hello</p><p><a href="https://www.iana.org/domains/example">More information...</a></p></div></body></html>`
	fuzzXMLCorpus      = `<?xml version="1.0"?><root><item id="alpha">A</item><item id="beta">B</item><link href="https://example.com">Example</link></root>`
)

type fuzzExtractorCandidate struct {
	extractorType           ExtractorType
	part                    string
	name                    string
	attribute               string
	internal                bool
	caseInsensitive         bool
	explicitCaseInsensitive bool
	regexGroup              int
	values                  []string
}

func extractorFromFuzzData(data []byte) (*Extractor, bool) {
	if len(data) == 0 || len(data) > fuzzMaxInputSize {
		return nil, false
	}

	candidate := newFuzzExtractorCandidate(data)
	candidate.applyLines(splitFuzzLines(data))
	candidate.addFallbackValues(data)

	return candidate.build()
}

func newFuzzExtractorCandidate(data []byte) *fuzzExtractorCandidate {
	flags := fuzzByteAt(data, 1)
	return &fuzzExtractorCandidate{
		extractorType:   fuzzExtractorTypes[int(fuzzByteAt(data, 0))%len(fuzzExtractorTypes)],
		part:            fuzzParts[int(fuzzByteAt(data, 2))%len(fuzzParts)],
		name:            fuzzName(data),
		attribute:       fuzzAttributes[int(fuzzByteAt(data, 3))%len(fuzzAttributes)],
		internal:        flags&0x01 != 0,
		caseInsensitive: flags&0x02 != 0,
		regexGroup:      int(fuzzByteAt(data, 4) % 3),
	}
}

func (candidate *fuzzExtractorCandidate) applyLines(lines []string) {
	for _, line := range lines {
		key, rawValue, ok := cutFuzzKV(line)
		if !ok {
			candidate.addValue(line)
			continue
		}

		switch key {
		case "type":
			extractorType, err := toExtractorTypes(rawValue)
			if err != nil {
				candidate.extractorType = ExtractorType(0)
			} else {
				candidate.extractorType = extractorType
			}
		case "part":
			candidate.part = trimFuzzValue(rawValue)
		case "name":
			candidate.name = fuzzNameFromText(rawValue)
		case "attribute":
			candidate.attribute = fuzzAttribute(rawValue)
		case "internal":
			candidate.internal = parseFuzzBool(rawValue, candidate.internal)
		case "case-insensitive":
			candidate.caseInsensitive = parseFuzzBool(rawValue, candidate.caseInsensitive)
			candidate.explicitCaseInsensitive = true
		case "group":
			candidate.regexGroup = parseFuzzGroup(rawValue, candidate.regexGroup)
		case "value":
			candidate.addValue(rawValue)
		case "regex":
			candidate.extractorType = RegexExtractor
			candidate.addValue(rawValue)
		case "kval":
			candidate.extractorType = KValExtractor
			candidate.addValue(rawValue)
		case "json":
			candidate.extractorType = JSONExtractor
			candidate.addValue(rawValue)
		case "xpath":
			candidate.extractorType = XPathExtractor
			candidate.addValue(rawValue)
		case "dsl":
			candidate.extractorType = DSLExtractor
			candidate.addValue(rawValue)
		}
	}
}

func (candidate *fuzzExtractorCandidate) addFallbackValues(payload []byte) {
	if len(candidate.values) > 0 || len(candidate.values) >= fuzzMaxItems {
		return
	}

	fields := splitFuzzFields(payload)
	switch candidate.extractorType {
	case RegexExtractor:
		for _, field := range fields {
			candidate.addValue(fuzzRegexValue(field))
		}
		candidate.addDefaults(fuzzRegexDefaults, fuzzByteAt(payload, 5))
	case KValExtractor:
		for _, field := range fields {
			candidate.addValue(fuzzIdentifier(field))
		}
		candidate.addDefaults(fuzzKValDefaults, fuzzByteAt(payload, 5))
	case JSONExtractor:
		for _, field := range fields {
			candidate.addValue(fuzzJSONQuery(field))
		}
		candidate.addDefaults(fuzzJSONDefaults, fuzzByteAt(payload, 5))
	case XPathExtractor:
		for _, field := range fields {
			candidate.addValue(fuzzXPathQuery(field))
		}
		candidate.addDefaults(fuzzXPathDefaults, fuzzByteAt(payload, 5))
	case DSLExtractor:
		for _, field := range fields {
			candidate.addValue(fuzzDSLExpression(field))
		}
		candidate.addDefaults(fuzzDSLDefaults, fuzzByteAt(payload, 5))
	default:
		candidate.addDefaults(fuzzRegexDefaults, fuzzByteAt(payload, 5))
	}
}

func (candidate *fuzzExtractorCandidate) addDefaults(defaults []string, seed byte) {
	if len(candidate.values) >= fuzzMaxItems || len(defaults) == 0 {
		return
	}

	start := int(seed) % len(defaults)
	for offset := 0; offset < len(defaults) && len(candidate.values) < 2; offset++ {
		candidate.addValue(defaults[(start+offset)%len(defaults)])
	}
}

func (candidate *fuzzExtractorCandidate) addValue(value string) {
	value = trimFuzzValue(value)
	if value == "" || len(candidate.values) >= fuzzMaxItems {
		return
	}
	for _, existing := range candidate.values {
		if existing == value {
			return
		}
	}
	candidate.values = append(candidate.values, value)
}

func (candidate *fuzzExtractorCandidate) build() (*Extractor, bool) {
	extractor := &Extractor{
		Type:       ExtractorTypeHolder{ExtractorType: candidate.extractorType},
		Name:       candidate.name,
		Part:       candidate.part,
		Internal:   candidate.internal,
		Attribute:  candidate.attribute,
		RegexGroup: candidate.regexGroup,
	}

	if candidate.extractorType == KValExtractor || candidate.explicitCaseInsensitive {
		extractor.CaseInsensitive = candidate.caseInsensitive
	}
	if candidate.extractorType != XPathExtractor {
		extractor.Attribute = ""
	}
	if candidate.extractorType != RegexExtractor {
		extractor.RegexGroup = 0
	}

	switch candidate.extractorType {
	case RegexExtractor:
		extractor.Regex = append([]string(nil), candidate.values...)
	case KValExtractor:
		extractor.KVal = append([]string(nil), candidate.values...)
	case XPathExtractor:
		extractor.XPath = append([]string(nil), candidate.values...)
	case JSONExtractor:
		extractor.JSON = append([]string(nil), candidate.values...)
	case DSLExtractor:
		extractor.DSL = append([]string(nil), candidate.values...)
	default:
		extractor.Regex = append([]string(nil), candidate.values...)
	}

	return extractor, len(candidate.values) > 0
}

func exerciseFuzzExtractor(extractor *Extractor) {
	switch extractor.GetType() {
	case RegexExtractor:
		_ = extractor.ExtractRegex(fuzzRegexCorpus)
	case KValExtractor:
		_ = extractor.ExtractKval(fuzzKValData())
	case XPathExtractor:
		_ = extractor.ExtractXPath(fuzzHTMLCorpus)
		_ = extractor.ExtractXPath(fuzzXMLCorpus)
	case JSONExtractor:
		_ = extractor.ExtractJSON(fuzzJSONCorpus)
	case DSLExtractor:
		_ = extractor.ExtractDSL(fuzzDSLData())
	}
}

func fuzzKValData() map[string]interface{} {
	return map[string]interface{}{
		"content_type": "Text/HTML",
		"server":       "Nginx",
		"set_cookie":   "session=abc123",
		"x_powered_by": "Go",
	}
}

func fuzzDSLData() map[string]interface{} {
	return map[string]interface{}{
		"hello":        "hi",
		"body":         "PING PONG",
		"all_headers":  "Server: Example\nContent-Type: text/html",
		"content_type": "text/html",
		"status_code":  200,
	}
}

func splitFuzzLines(data []byte) []string {
	fields := strings.FieldsFunc(string(data), func(r rune) bool {
		return r == '\n' || r == '\r' || r == ';'
	})
	if len(fields) > fuzzMaxItems*4 {
		fields = fields[:fuzzMaxItems*4]
	}

	lines := make([]string, 0, len(fields))
	for _, field := range fields {
		field = trimFuzzValue(field)
		if field != "" {
			lines = append(lines, field)
		}
	}
	return lines
}

func splitFuzzFields(data []byte) []string {
	fields := strings.FieldsFunc(string(data), func(r rune) bool {
		return r == '\n' || r == '\r' || r == '|' || r == ','
	})
	if len(fields) > fuzzMaxItems {
		fields = fields[:fuzzMaxItems]
	}

	values := make([]string, 0, len(fields))
	for _, field := range fields {
		field = trimFuzzValue(field)
		if field != "" {
			values = append(values, field)
		}
	}
	return values
}

func cutFuzzKV(line string) (string, string, bool) {
	key, value, ok := strings.Cut(line, "=")
	if !ok {
		key, value, ok = strings.Cut(line, ":")
	}
	if !ok {
		return "", "", false
	}
	return strings.ToLower(strings.TrimSpace(key)), trimFuzzValue(value), true
}

func trimFuzzValue(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\x00", ""))
	if len(value) > fuzzMaxValueBytes {
		value = value[:fuzzMaxValueBytes]
	}
	return value
}

func fuzzName(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	if len(data) > 8 {
		data = data[:8]
	}
	return "fuzz-" + strconv.FormatUint(uint64(data[0]), 16) + fuzzNameSuffix(data[1:])
}

func fuzzNameSuffix(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	var builder strings.Builder
	for _, value := range data {
		if builder.Len() >= 15 {
			break
		}
		builder.WriteString(strconv.FormatUint(uint64(value), 16))
	}
	return builder.String()
}

func fuzzNameFromText(value string) string {
	value = strings.ToLower(trimFuzzValue(value))
	if value == "" {
		return ""
	}
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-':
			builder.WriteRune(r)
		}
		if builder.Len() >= 32 {
			break
		}
	}
	if builder.Len() == 0 {
		return ""
	}
	return builder.String()
}

func fuzzAttribute(value string) string {
	attribute := fuzzIdentifier(value)
	if attribute == "" {
		return trimFuzzValue(value)
	}
	return attribute
}

func parseFuzzBool(value string, fallback bool) bool {
	switch strings.ToLower(trimFuzzValue(value)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func parseFuzzGroup(value string, fallback int) int {
	number, err := strconv.Atoi(trimFuzzValue(value))
	if err != nil {
		return fallback
	}
	if number < -2 {
		return -2
	}
	if number > 8 {
		return 8
	}
	return number
}

func fuzzRegexValue(value string) string {
	value = trimFuzzValue(value)
	if value == "" {
		return ""
	}
	return regexp.QuoteMeta(value)
}

func fuzzJSONQuery(value string) string {
	identifier := fuzzIdentifier(value)
	if identifier == "" {
		return ""
	}
	return "." + identifier
}

func fuzzXPathQuery(value string) string {
	identifier := fuzzIdentifier(value)
	if identifier == "" {
		return ""
	}
	return "//" + identifier
}

func fuzzDSLExpression(value string) string {
	identifier := fuzzIdentifier(value)
	if identifier == "" {
		return ""
	}
	switch identifier {
	case "hello", "body", "all_headers", "content_type":
		return "to_upper(" + identifier + ")"
	case "status_code":
		return identifier
	default:
		return identifier
	}
}

func fuzzIdentifier(value string) string {
	value = strings.ToLower(trimFuzzValue(value))
	if value == "" {
		return ""
	}
	var builder strings.Builder
	lastUnderscore := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
			lastUnderscore = false
		case r >= '0' && r <= '9':
			if builder.Len() == 0 {
				builder.WriteString("field_")
			}
			builder.WriteRune(r)
			lastUnderscore = false
		case r == '_' || r == '-' || r == '.' || r == ' ':
			if builder.Len() > 0 && !lastUnderscore {
				builder.WriteByte('_')
				lastUnderscore = true
			}
		}
		if builder.Len() >= 32 {
			break
		}
	}
	return strings.Trim(builder.String(), "_")
}

func fuzzByteAt(data []byte, index int) byte {
	if index < 0 || index >= len(data) {
		return 0
	}
	return data[index]
}
