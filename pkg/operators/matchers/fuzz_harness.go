package matchers

import (
	"encoding/hex"
	"strconv"
	"strings"
)

const (
	fuzzMaxInputSize  = 16 << 10
	fuzzMaxItems      = 8
	fuzzMaxValueBytes = 256
)

var (
	fuzzMatcherTypes = []MatcherType{WordsMatcher, RegexMatcher, BinaryMatcher, StatusMatcher, SizeMatcher, DSLMatcher, XPathMatcher}
	fuzzConditions   = []string{"", "and", "or"}
	fuzzEncodings    = []string{"", "hex"}
	fuzzParts        = []string{"", "body", "raw", "all_headers", "header", "response"}
)

type fuzzMatcherCandidate struct {
	matcherType     MatcherType
	condition       string
	part            string
	encoding        string
	name            string
	negative        bool
	caseInsensitive bool
	matchAll        bool
	values          []string
	status          []int
	size            []int
}

func matcherFromFuzzData(data []byte) (*Matcher, bool) {
	if len(data) == 0 || len(data) > fuzzMaxInputSize {
		return nil, false
	}

	payload := data

	candidate := newFuzzMatcherCandidate(data)
	candidate.applyLines(splitFuzzLines(payload))
	candidate.addFallbackValues(payload)
	candidate.addFallbackIntegers(payload)

	return candidate.build()
}

func newFuzzMatcherCandidate(data []byte) *fuzzMatcherCandidate {
	flags := fuzzByteAt(data, 1)
	return &fuzzMatcherCandidate{
		matcherType:     fuzzMatcherTypes[int(fuzzByteAt(data, 0))%len(fuzzMatcherTypes)],
		condition:       fuzzConditions[int(fuzzByteAt(data, 1))%len(fuzzConditions)],
		part:            fuzzParts[int(fuzzByteAt(data, 2))%len(fuzzParts)],
		encoding:        fuzzEncodings[int(fuzzByteAt(data, 3))%len(fuzzEncodings)],
		name:            fuzzName(data),
		negative:        flags&0x01 != 0,
		caseInsensitive: flags&0x02 != 0,
		matchAll:        flags&0x04 != 0,
	}
}

func (candidate *fuzzMatcherCandidate) applyLines(lines []string) {
	for _, line := range lines {
		key, rawValue, ok := cutFuzzKV(line)
		if !ok {
			candidate.addValue(line)
			continue
		}

		switch key {
		case "type":
			matcherType, err := toMatcherTypes(rawValue)
			if err != nil {
				candidate.matcherType = MatcherType(0)
			} else {
				candidate.matcherType = matcherType
			}
		case "condition":
			candidate.condition = trimFuzzValue(rawValue)
		case "part":
			candidate.part = trimFuzzValue(rawValue)
		case "encoding":
			candidate.encoding = trimFuzzValue(rawValue)
		case "name":
			candidate.name = fuzzNameFromText(rawValue)
		case "negative":
			candidate.negative = parseFuzzBool(rawValue, candidate.negative)
		case "case-insensitive":
			candidate.caseInsensitive = parseFuzzBool(rawValue, candidate.caseInsensitive)
		case "match-all":
			candidate.matchAll = parseFuzzBool(rawValue, candidate.matchAll)
		case "value":
			candidate.addValue(rawValue)
		case "word":
			candidate.matcherType = WordsMatcher
			candidate.addValue(rawValue)
		case "regex":
			candidate.matcherType = RegexMatcher
			candidate.addValue(rawValue)
		case "binary":
			candidate.matcherType = BinaryMatcher
			candidate.addValue(rawValue)
		case "dsl":
			candidate.matcherType = DSLMatcher
			candidate.addValue(rawValue)
		case "xpath":
			candidate.matcherType = XPathMatcher
			candidate.addValue(rawValue)
		case "status":
			candidate.matcherType = StatusMatcher
			candidate.status = append(candidate.status, fuzzParseStatuses(rawValue)...)
		case "size":
			candidate.matcherType = SizeMatcher
			candidate.size = append(candidate.size, fuzzParseSizes(rawValue)...)
		}
	}
}

func (candidate *fuzzMatcherCandidate) addFallbackValues(payload []byte) {
	if len(candidate.values) > 0 || len(candidate.values) >= fuzzMaxItems {
		return
	}

	for _, value := range splitFuzzFields(payload) {
		candidate.addValue(value)
		if len(candidate.values) >= fuzzMaxItems {
			return
		}
	}
}

func (candidate *fuzzMatcherCandidate) addFallbackIntegers(payload []byte) {
	if len(candidate.status) == 0 {
		candidate.status = append(candidate.status, fuzzStatusValue(int(fuzzByteAt(payload, 0))))
		candidate.status = append(candidate.status, fuzzStatusValue(int(fuzzByteAt(payload, 1))))
	}
	if len(candidate.size) == 0 {
		candidate.size = append(candidate.size, fuzzSizeValue(int(fuzzByteAt(payload, 2))|(int(fuzzByteAt(payload, 3))<<8)))
		candidate.size = append(candidate.size, fuzzSizeValue(int(fuzzByteAt(payload, 4))|(int(fuzzByteAt(payload, 5))<<8)))
	}
}

func (candidate *fuzzMatcherCandidate) addValue(value string) {
	value = trimFuzzValue(value)
	if value == "" || len(candidate.values) >= fuzzMaxItems {
		return
	}
	candidate.values = append(candidate.values, value)
}

func (candidate *fuzzMatcherCandidate) build() (*Matcher, bool) {
	matcher := &Matcher{
		Type:            MatcherTypeHolder{MatcherType: candidate.matcherType},
		Condition:       candidate.condition,
		Part:            candidate.part,
		Negative:        candidate.negative,
		Name:            candidate.name,
		Encoding:        candidate.encoding,
		CaseInsensitive: candidate.caseInsensitive,
		MatchAll:        candidate.matchAll,
	}

	switch candidate.matcherType {
	case DSLMatcher:
		matcher.Part = ""
		matcher.Encoding = ""
		matcher.CaseInsensitive = false
	case StatusMatcher, SizeMatcher:
		matcher.Encoding = ""
		matcher.CaseInsensitive = false
	case XPathMatcher:
		matcher.Encoding = ""
		matcher.CaseInsensitive = false
	case RegexMatcher, BinaryMatcher:
		matcher.CaseInsensitive = false
	}

	switch candidate.matcherType {
	case WordsMatcher:
		matcher.Words = append([]string(nil), candidate.values...)
	case RegexMatcher:
		matcher.Regex = append([]string(nil), candidate.values...)
	case BinaryMatcher:
		matcher.Binary = append([]string(nil), candidate.values...)
	case DSLMatcher:
		matcher.DSL = append([]string(nil), candidate.values...)
	case XPathMatcher:
		matcher.XPath = append([]string(nil), candidate.values...)
	case StatusMatcher:
		matcher.Status = append([]int(nil), candidate.status...)
	case SizeMatcher:
		matcher.Size = append([]int(nil), candidate.size...)
	default:
		matcher.Words = append([]string(nil), candidate.values...)
	}

	if matcher.GetType() == StatusMatcher || matcher.GetType() == SizeMatcher {
		return matcher, len(matcher.Status) > 0 || len(matcher.Size) > 0
	}
	return matcher, len(candidate.values) > 0
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
	return "fuzz-" + hex.EncodeToString(data)
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

func fuzzParseStatuses(value string) []int {
	parsed := fuzzParseNumbers(value)
	statuses := make([]int, 0, len(parsed))
	for _, number := range parsed {
		statuses = append(statuses, fuzzStatusValue(number))
	}
	return statuses
}

func fuzzParseSizes(value string) []int {
	parsed := fuzzParseNumbers(value)
	sizes := make([]int, 0, len(parsed))
	for _, number := range parsed {
		sizes = append(sizes, fuzzSizeValue(number))
	}
	return sizes
}

func fuzzParseNumbers(value string) []int {
	tokens := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '|' || r == ' ' || r == '\t'
	})
	if len(tokens) > fuzzMaxItems {
		tokens = tokens[:fuzzMaxItems]
	}

	parsed := make([]int, 0, len(tokens))
	for _, token := range tokens {
		token = trimFuzzValue(token)
		if token == "" {
			continue
		}
		number, err := strconv.Atoi(token)
		if err != nil {
			number = 0
			for i := 0; i < len(token); i++ {
				number += int(token[i])
			}
		}
		parsed = append(parsed, number)
	}
	return parsed
}

func fuzzStatusValue(number int) int {
	if number >= 100 && number <= 599 {
		return number
	}
	if number < 0 {
		number = -number
	}
	return 100 + (number % 500)
}

func fuzzSizeValue(number int) int {
	if number > 0 && number <= 1<<20 {
		return number
	}
	if number < 0 {
		number = -number
	}
	return 1 + (number % (1 << 16))
}

func fuzzByteAt(data []byte, index int) byte {
	if index < 0 || index >= len(data) {
		return 0
	}
	return data[index]
}
